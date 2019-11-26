#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include "cJSON.h"

#define CONFILE "/etc/suricata/ids_mysql.conf"

MYSQL mysql;
char mysqlUserName[128] ;
char mysqlPasswd[128] ;
char mysqlDbName[128];

int ParseConf()
{
	FILE *fp = fopen(CONFILE, "r");

	if (!fp ) {
		printf("Failed to open file %s \n", CONFILE);
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




int MysqlInit()
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

int ConvertEve()
{

}

int main()
{

	if (ParseConf() < 0)
		return -1;

	if (MysqlInit() < 0) 
		return -1;

	if (ConvertEve() < 0) 
		return -1;

	return 0;
}
