#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include "cJSON.h"

#define FILE_LINE_LEN 4089

#define dbg(fmt, args...) printf("\033[33m[%s:%s:%d]\033[0m "#fmt"\r\n", __FILE__, __func__, __LINE__, ##args);

char ids_mysql_conf[128]; 
char ids_eve_file[128];
long g_curr_offset = 0;

MYSQL mysql;
char mysqlUserName[128] ;
char mysqlPasswd[128] ;
char mysqlDbName[128];


int parse_mysql_conf()
{
	FILE *fp = fopen(ids_mysql_conf, "r");

	if (!fp ) {
		printf("Failed to open file %s \n", ids_mysql_conf);
		return -1;
	}
	char buf[256] = {0};
	char key[256];
	char val[256];
	while (fgets(buf, sizeof(buf), fp) != NULL) {

		char *pb = buf;
		char *end = buf + strlen(buf);
		int i =0;
		while (pb != end) {
			if (*pb == '#')
				buf[i] = '\0';
			pb ++;
			i++;
		}

		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		sscanf(buf, "%[^=]=%s[^=]", key, val);
		//printf("key=%s,  val=%s\n", key, val);

		if (strncmp(key, "username", strlen("username")) == 0) {
			strncpy(mysqlUserName, val, 128);
		} else if (strncmp(key, "passwd",strlen("passwd")) == 0) {
			strncpy(mysqlPasswd, val, 128);
		} else if (strncmp(key, "dbname",strlen("dbname")) == 0) {
			strncpy(mysqlDbName, val, 128);
		}

	}

	fclose(fp);

	return 0;
}




int create_mysql()
{

	if (NULL == mysql_init(&mysql)) {
		printf("mysql_init(): %s\n", mysql_error(&mysql));
		mysql_close(&mysql);
		return -1;
	}


	if (NULL == mysql_real_connect(&mysql, "localhost", mysqlUserName, mysqlPasswd, mysqlDbName, 0, NULL, 0)) {
		printf("mysql_real_connect(): %s\n", mysql_error(&mysql));
		mysql_close(&mysql);
		return -1;
	}

	mysql_set_character_set(&mysql, "utf8");

	return 0;
}
/*
 * json data example:
 *
 {"timestamp":"2019-11-26T16:41:02.504203+0800","flow_id":1785133986132363,"in_iface":"ens33","event_type":"alert","src_ip":"10.8.8.1","src_port":57649,"dest_ip":"10.8.8.66","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":100001,"rev":7,"signature":"ssh test ","category":"Executable code was detected","severity":1},"flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":102,"bytes_toclient":0,"start":"2019-11-26T16:41:02.504203+0800"},"payload":"wKWSDXVfI9Stnk+pLIkOEQ8VZntQ0pj4RmIreFIvQGgUaJkX","stream":0}
 */

int parse_evejson(char *data)
{
	if (!data)
		return -1;

	char query_statement[1500]; 
	char json_value[1024];

	cJSON* root = cJSON_Parse(data);
	cJSON* item_timestatmp = cJSON_GetObjectItem(root, "timestamp");
	cJSON* item_srcip = cJSON_GetObjectItem(root, "src_ip");
	cJSON* item_srcport = cJSON_GetObjectItem(root, "src_port");
	cJSON* item_dstip = cJSON_GetObjectItem(root, "dest_ip");
	cJSON* item_dstport = cJSON_GetObjectItem(root, "dest_port");
	cJSON* item_proto = cJSON_GetObjectItem(root, "proto");

	cJSON* item_alert = cJSON_GetObjectItem(root, "alert");

	if (item_alert == NULL) 
		return -1;

	cJSON* item_sid = cJSON_GetObjectItem(item_alert, "signature_id");
	cJSON* item_rev = cJSON_GetObjectItem(item_alert, "rev");
	cJSON* item_msg = cJSON_GetObjectItem(item_alert, "signature");
	cJSON* item_category = cJSON_GetObjectItem(item_alert, "category");
	cJSON* item_severity = cJSON_GetObjectItem(item_alert, "severity");

	char timestamp[64]; 
	char srcip[64]; 
	int srcport;
	char dstip[128];
	int dstport;
	char proto[32]; 
	long sid; 
	int rev; 
	char msg[512]; 
	char category[128];
	int severity;


	if (item_sid == NULL )
		return -1;

	if (item_msg != NULL)
		strncpy(msg, item_msg->valuestring, sizeof(msg)); 
	else 
		memset(msg, 0, sizeof(msg)); 
				
	if (item_srcip != NULL) 
		strncpy(srcip, item_srcip->valuestring, sizeof(srcip));
	else 
		memset(srcip, 0, sizeof(srcip)); 

	if (item_srcport != NULL) 
		srcport = item_srcport->valueint;
	else 
		srcport = 0;
				
	if (item_dstip != NULL) 
		strncpy(dstip, item_dstip->valuestring, sizeof(dstip));
	else 
		memset(dstip, 0, sizeof(dstip)); 

	if (item_dstport!= NULL) 
		dstport = item_dstport->valueint;	
	else 
		dstport = 0;
	
	if (item_proto != NULL) 
		strncpy(proto, item_proto->valuestring, sizeof(proto));
	else 
		memset(proto, 0, sizeof(proto));

	if (item_category != NULL) 
		strncpy(category, item_category->valuestring, sizeof(category));
	else 
		memset(category, 0, sizeof(category));

	if (item_severity != NULL) 
		severity = item_severity->valueint;
	else 
		severity = 0;

	if (item_rev != NULL) 
		rev = item_rev->valueint;
	else 
		rev = 0;

	if (item_timestatmp != NULL) 
		strncpy(timestamp, item_timestatmp->valuestring, sizeof(timestamp));
	else 
		memset (timestamp, 0, sizeof(timestamp));

	sid = item_sid->valueint;

	snprintf(json_value, sizeof(json_value), "%ld,\"%s\",\"%s\",%d,\"%s\",\"%d\",\"%s\",\"%s\", %d,%d,\"%s\"", 
			sid, msg, srcip, srcport, dstip, dstport, proto, category, severity, rev, timestamp);

	snprintf(query_statement, sizeof(query_statement), "insert into  ids_alert_event(sid,msg,src_ip,src_port,dst_ip,dst_port,protocol,risk_category,risk_level,rule_version, create_time) value (%s)", json_value);

	dbg("%s", query_statement);

	int ret = mysql_query(&mysql, query_statement);
	if ( ret != 0) {
		dbg("mysql_query() error: %s", mysql_error(&mysql));
	}

	MYSQL_RES       *res = NULL;
	do {

		res = mysql_use_result(&mysql);
		mysql_free_result(res);
	} while (!mysql_next_result(&mysql));


	cJSON_Delete(root);

	return 0;
}


int convert_eve()
{
	
	FILE *fp = fopen(ids_eve_file, "r");
	if (!fp) {
		printf("can't open file, file: %s\n", ids_eve_file);
		return -1;
	}

	fseek(fp, g_curr_offset, SEEK_SET);

	char text[FILE_LINE_LEN];
    uint32_t len;
	while (!feof(fp)) {
		memset(text, 0x0, FILE_LINE_LEN);
		fgets(text, FILE_LINE_LEN, fp);
		len = strlen(text);

		if (len == 0 || text[len - 1] != '\n')
			continue;

		text[len - 1] = 0;
		g_curr_offset += len;

		if (strstr(text, "event_type\":\"alert\"") ) {
			dbg("%s", text);
			parse_evejson(text);
		}
	}

	fclose(fp);

	return 0;
}

int g_daemon;

void usage()
{
    printf("Usage:\n");
    printf("\teve2mysql -c <ids msql configure file>\n");
    printf("\t          -e <ids eve.json file>>\n");
    printf("\t          -d  run as background\n");
    printf("\t          -h  show this help informoation\n");
}

int parse_args(int argc, char **argv)
{
	int ch = -1;
	int is_ids_eve_file, is_ids_mysql_file;
	is_ids_eve_file =  is_ids_mysql_file = 0;
    while ((ch = getopt(argc, argv, "e:c:dh")) != -1) {
        switch (ch)
        {
            case 'e':
                strncpy(ids_eve_file, optarg, sizeof(ids_eve_file));
				is_ids_eve_file = 1;
                break;
            case 'c':
                strncpy(ids_mysql_conf, optarg, sizeof(ids_mysql_conf));
				is_ids_mysql_file = 1;
                break;
            case 'd':
                g_daemon = 1;
                break;
            case 'h':
            case '?':
            default :
                return -1;
        }
    }

	if (!is_ids_eve_file || !is_ids_mysql_file) {
		printf("must specify ids eve.json file and ids mysql configure file!\n");
		return -1;
	}

    return 0;
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv) < 0)  {
		usage();
		return -1;
	}

	if (g_daemon == 1) {
		daemon(1, 0);
	}

	if (parse_mysql_conf() < 0)
		return -1;

	if (create_mysql() < 0) 
		return -1;

	while (1) {
		if (convert_eve() < 0) 
			return -1;
	}

	return 0;
}
