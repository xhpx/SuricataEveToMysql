#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include "cJSON.h"

char ids_mysql_conf[128]; 
char ids_eve_file[128];

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

int convert_eve()
{

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
    int flg =0;
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

	if (convert_eve() < 0) 
		return -1;

	return 0;
}
