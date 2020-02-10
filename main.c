#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <mysql/mysql.h>
#include <pthread.h>
#include <librdkafka/rdkafka.h>
#include "cJSON.h"
#include "sfghash.h"
#include "b64.h"

#define FILE_LINE_LEN 4089
#define DEFAULT_IDS_EVE_FILE "/var/log/suricata/eve.json"
#define DEFAULT_IDS_MYSQL_CONF "/etc/suricata/ids_mysql.conf"

#define dbg(fmt, args...) printf("\033[33m[%s:%s:%d]\033[0m "#fmt"\r\n", __FILE__, __func__, __LINE__, ##args);

char ids_mysql_conf[128]; 
char ids_eve_file[128];
long g_curr_offset = 0;

int is_ids_eve_file, is_ids_mysql_file;
int is_enable_ids;
int is_log_kafka ;
int is_ssl;

rd_kafka_topic_t *rkt;
rd_kafka_t *rk;      
MYSQL mysql;
char mysqlUserName[128] ;
char mysqlPasswd[128] ;
char mysqlDbName[128];

char brokers[128];
char topic[128];
char kafka_passwd[128];
SFGHASH * sid_hash = NULL;

void thread_sleep(unsigned long sleepSecond)
{
    struct timeval t_timeval;
    t_timeval.tv_sec = (sleepSecond / 1000);
    t_timeval.tv_usec = (sleepSecond % 1000);
    select(0, NULL, NULL, NULL, &t_timeval);

    return;
}

long long get_cur_mstime()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	long long curtime = tv.tv_sec*1000*1000 + tv.tv_usec;

	return curtime;
}

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


void freehash ( void * p )
{
	free(p);
}

/*
 * return 1: enable
 * return 0: disable
 */
int read_enable_ids_flag()
{
	
	int is_kafka = 0;
	int fields, rc = 0;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char *query_str = "select * from sys_output_setting";
	rc = mysql_real_query(&mysql, query_str, strlen(query_str));
	if (0 != rc) {
		printf("mysql_real_query(): %s\n", mysql_error(&mysql));
		return -1;
	}
	res = mysql_store_result(&mysql);

	if (NULL == res) {
		printf("mysql_restore_result(): %s\n", mysql_error(&mysql));
		return -1;
	}

	fields = mysql_num_fields(res);
	while ((row = mysql_fetch_row(res))) {
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(res);
		int i;
		for (i = 0; i < fields; i++) {
			if (i == 1) {
				if (lengths[i] > 0 || row[i] != NULL) {
					if (strstr(row[i], "kafka输出") != NULL)
						is_kafka = 1;
				}
			}

			if (i == 3) {
				if (lengths[i] > 0 || row[i] != NULL) {
					if (strstr(row[i], "入侵检测") != NULL)
						if (is_kafka == 1) {
							is_enable_ids = 1;
							is_kafka = 0;
						}
				}
			}


			if (i == 4) {
				if (lengths[i] > 0 || row[i] != NULL) {
					if (atoi(row[i]) == 1)
						is_log_kafka = 1;
				}
			}

			if (i == 6) {
				if (lengths[i] > 0 || row[i] != NULL) {
					is_ssl = atoi(row[i]);
				}
			}

			if (i == 7) {
				if (lengths[i] > 0 || row[i] != NULL) {
					snprintf(brokers, sizeof(brokers), "%s", row[i]);
				}
			}

			if (i == 8) {
				if (lengths[i] > 0 || row[i] != NULL) {
					snprintf(kafka_passwd, sizeof(kafka_passwd), "%s", row[i]);
				}
			}

			if (i == 12) {
				if (lengths[i] > 0 || row[i] != NULL) {
					snprintf(topic, sizeof(topic), "%s", row[i]);
				}
			}
		}

	}

	mysql_free_result(res);

	return 0;
}
void * read_ids_flag_func(void* data)
{
	while (1) {
		read_enable_ids_flag();
		thread_sleep(5000);
	}

}


static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
		if(rkmessage->err)
			fprintf(stderr, "%% Message delivery failed: %s\n",
					rd_kafka_err2str(rkmessage->err));
		else
			fprintf(stderr,
                        "%% Message delivered (%zd bytes, "
                        "partition %"PRId32")\n",
                        rkmessage->len, rkmessage->partition);
}

int kafka_init()
{
	char errstr[512];

	rd_kafka_conf_t *conf;
	conf = rd_kafka_conf_new();

	if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
				sizeof(errstr)) != RD_KAFKA_CONF_OK){
		fprintf(stderr, "%s\n", errstr);
		return -1;
	}

	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if(!rk){
		fprintf(stderr, "%% Failed to create new producer:%s\n", errstr);
		rd_kafka_conf_destroy(conf);
		return -1;
	}

	rkt = rd_kafka_topic_new(rk, topic, NULL);
	if (!rkt){
		fprintf(stderr, "%% Failed to create topic object: %s\n",
				rd_kafka_err2str(rd_kafka_last_error()));
		rd_kafka_destroy(rk);
		return -1;
	}

	return 0;
}
int init()
{

	 sid_hash = sfghash_new( 10000, 0 , 0, freehash);

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


	pthread_t id1;

	if (pthread_create(&id1, NULL, read_ids_flag_func, NULL)) {
		printf( "Failed to start Read Enable IDS Flag Thread\n");
		return -1;
	}

	if (is_log_kafka)
		kafka_init();


	return 0;
}

int write_to_db(char* query_statement)
{
	int ret = mysql_query(&mysql, query_statement);
	if ( ret != 0) {
		dbg("mysql_query() error: %s", mysql_error(&mysql));
	} 

	MYSQL_RES       *res = NULL;
	do {

		res = mysql_use_result(&mysql);
		mysql_free_result(res);
	} while (!mysql_next_result(&mysql));

	return 0;
}

//{log_type:"3",id:"id1",equ_ip:"equ_ip1",equ_asset_name:"equ_asset_name1",create_time:"create_time1",severity:"severity1",src_ip:"src_ip1",src_mac:"src_mac1",src_port:"src_port1",src_asset_name:"src_asset_name1",protocol:"protocol1",dst_ip:"dst_ip1",dst_mac:"dst_mac1",dst_port:"dst_port1",dst_asset_name:"dst_asset_name1",src_user_name:"src_user_name1",src_dept_name:"src_dept_name1",dst_user_name:"dst_user_name1",dst_dept_name:"dst_dept_name1",event_name:"event_name1",event_desc:"event_desc1",event_category:"event_category1",event_status:"event_status1"}  
int write_to_kafka(char* kafka_string)
{
	int times = 0;
	size_t len = strlen(kafka_string);
	
	while (times <= 3 ) {
		if (rd_kafka_produce( rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, kafka_string, len,
					NULL, 0, NULL) == -1){
			fprintf(stderr, "%% Failed to produce to topic %s: %s\n",
					rd_kafka_topic_name(rkt), rd_kafka_err2str(rd_kafka_last_error()));

			if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL){
				rd_kafka_poll(rk, 1000);
				times ++;
				continue;
			}
		}else{
			fprintf(stderr, "%% Enqueued message (%zd bytes) for topic %s\n",
					len, rd_kafka_topic_name(rkt));
		}
	}

	return 0;
}

int is_ipv6(char *s)
{
	int len = strlen(s);
	if (s[0] == ':' || s[len - 1] == ':')
		return 0;
	int count_colon = 0;
	int count_bit=0;
	int i;
	for (i = 0; i < len; i++) {
		if ((s[i]<'a' || s[i] > 'f') && (s[i] < 'A' || s[i] > 'F') && (s[i] < '0' || s[i] > '9')&&s[i]!=':')
			return 0;
		count_bit++;
		if (s[i] == ':') {
			count_bit = 0;
			count_colon++;
			if (s[i + 1] == ':')
				return 0;
		}
		if (count_bit > 4)
			return 0;
	}
	if (count_colon != 7)
		return 0;

	return 1;
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
	char kafka_string[1500]; 
	char json_value[1024];

	cJSON* root = cJSON_Parse(data);
	cJSON* item_timestatmp = cJSON_GetObjectItem(root, "timestamp");
	cJSON* item_srcip = cJSON_GetObjectItem(root, "src_ip");
	cJSON* item_srcport = cJSON_GetObjectItem(root, "src_port");
	cJSON* item_dstip = cJSON_GetObjectItem(root, "dest_ip");
	cJSON* item_dstport = cJSON_GetObjectItem(root, "dest_port");
	cJSON* item_proto = cJSON_GetObjectItem(root, "proto");

	cJSON* item_alert = cJSON_GetObjectItem(root, "alert");
	cJSON* item_payload = cJSON_GetObjectItem(root, "payload");

	cJSON* item_payload_printable = cJSON_GetObjectItem(root, "payload_printable");

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
	char payload[4096];
	char payload_printable[4096];

	char *event_result = "成功";

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

	if (item_payload != NULL) {
		strncpy(payload, item_payload->valuestring, sizeof(payload));
	} else  {
		memset(payload, 0, sizeof(payload));
	}
	
	unsigned char *payload_hex = b64_decode(payload, strlen(payload));
	dbg("payload    : %s", payload);
	dbg("payload hex: %s", payload_hex);

	if (item_payload_printable != NULL) 
		strncpy(payload_printable, item_payload_printable->valuestring, sizeof(payload_printable));
	else  
		memset(payload_printable, 0, sizeof(payload_printable));

	sid = item_sid->valueint;

	
	/*
	snprintf(json_value, sizeof(json_value), "%ld,\"%s\",\"%s\",%d,\"%s\",\"%d\",\"%s\",\"%s\", %d,%d,\"%s\"", 
			sid, msg, srcip, srcport, dstip, dstport, proto, category, severity, rev, timestamp);

	snprintf(query_statement, sizeof(query_statement), "insert into  ids_alert_event(sid,msg,src_ip,src_port,dst_ip,dst_port,protocol,risk_category,risk_level,rule_version, create_time) value (%s)", json_value);
	*/

	char ip_type[16]= "";
	if (is_ipv6(srcip) ) 
		strcpy(ip_type, "ipv6");
	else 
		strcpy(ip_type, "ipv4");

	char *fmt = "\"%ld\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%d\",\"%s\",\"%d\",  \"%s\",\"%s\",\"%s\",\"%s\", \"%s\",\"%d\"";

    snprintf(json_value, sizeof(json_value), fmt, sid, " ", " ", msg, category, srcip, " ", dstip," ",srcport,dstport,proto,severity, event_result, payload_hex, payload_printable,timestamp, ip_type, rev);
    snprintf(query_statement, sizeof(query_statement), "insert into  audit_log_invade_event(sid,engine_name,engine_ip,event_name,event_type,source_ip,source_mac,dst_ip,dst_mac,source_port,dst_port,protocol,risk_level,event_result,original_message_16binary,original_message,create_time,ip_type,rule_rev) value (%s)", json_value);

	long long current_time = get_cur_mstime()/1000;

	char key[256];
	snprintf(key, sizeof(key), "%ld, %s, %d, %s, %d", sid, srcip, srcport, dstip, dstport);
	char string_time[32];
	snprintf(string_time, sizeof(string_time), "%lld", current_time);


//{log_type:"3",id:"id1",equ_ip:"equ_ip1",equ_asset_name:"equ_asset_name1",create_time:"create_time1",severity:"severity1",src_ip:"src_ip1",src_mac:"src_mac1",src_port:"src_port1",src_asset_name:"src_asset_name1",protocol:"protocol1",dst_ip:"dst_ip1",dst_mac:"dst_mac1",dst_port:"dst_port1",dst_asset_name:"dst_asset_name1",src_user_name:"src_user_name1",src_dept_name:"src_dept_name1",dst_user_name:"dst_user_name1",dst_dept_name:"dst_dept_name1",event_name:"event_name1",event_desc:"event_desc1",event_category:"event_category1",event_status:"event_status1"}  

	snprintf(kafka_string, sizeof(kafka_string),"{log_type:\"3\",id:\" \",equ_ip:\" \",equ_asset_name:\" \",create_time:\"%s\",severity:%d,src_ip:\"%s\",src_mac:\" \",src_port:%d,src_asset_name:\" \",protocol:\" \",dst_ip:\"%s\",dst_mac:\" \",dst_port:%d,dst_asset_name:\" \",src_user_name:\" \",src_dept_name:\" \",dst_user_name:\" \",dst_dept_name:\" \",event_name:\"%s\",event_desc:\" \",event_category:\"%s\",event_status:0}",timestamp, severity, srcip, srcport, dstip, dstport,msg, category );

	char *ret_time = (char*) sfghash_find(sid_hash, key);
	if (ret_time != NULL) {
		if (current_time - atoll(ret_time) > 10000) {
			write_to_db(query_statement);
			if (is_log_kafka)
				write_to_kafka(kafka_string);
			dbg("%s", query_statement);
			sfghash_remove(sid_hash, key);
			int ret = sfghash_add2(sid_hash, key, string_time);
			if ( ret == SFGHASH_OK) {
				dbg("added key:%s, val: %s", key, string_time );
			}else if (ret == SFGHASH_NOMEM) {
				dbg("no memory!");
			} else if (ret == SFGHASH_ERR) {
				dbg("add error!");
			}
		}
		cJSON_Delete(root);
	} else {
		write_to_db(query_statement);
		if (is_log_kafka)
			write_to_kafka(kafka_string);
		dbg("%s", query_statement);
		int ret = sfghash_add2(sid_hash, key, string_time);
		if ( ret == SFGHASH_OK) {
			dbg("added key:%s, val: %s", key, string_time );
		}else if (ret == SFGHASH_NOMEM) {
			dbg("no memory!");
		} else if (ret == SFGHASH_ERR) {
			dbg("add error!");
		}


		cJSON_Delete(root);
	}

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
    printf("\teve2mysql -c <ids msql configure file> default:\"/etc/suricata/ids_mysql.conf\"\n");
    printf("\t          -e <ids eve.json file> default:\"/var/log/suricata/eve.json\"\n");
    printf("\t          -d  run as background\n");
    printf("\t          -h  show this help informoation\n");
}

int parse_args(int argc, char **argv)
{
	int ch = -1;
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

	/*
	if (!is_ids_eve_file || !is_ids_mysql_file) {
		printf("must specify ids eve.json file and ids mysql configure file!\n");
		return -1;
	}
	*/

	if (is_ids_mysql_file == 0) {
		strncpy(ids_mysql_conf, DEFAULT_IDS_MYSQL_CONF, sizeof(ids_mysql_conf));
	}

	if (is_ids_eve_file == 0) {
		strncpy(ids_eve_file, DEFAULT_IDS_EVE_FILE, sizeof(ids_eve_file));
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

	if (init() < 0) 
		return -1;

	while (1) {
		if (convert_eve() < 0) 
			return -1;
	}

	return 0;
}
