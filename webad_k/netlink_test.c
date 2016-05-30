#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>

#define NETLINK_TEST 31 
#define MSG_LEN 4096
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
#pragma pack(push)
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

struct msg_to_kernel
{
    struct nlmsghdr hdr;
    char data[MSG_LEN];
};
struct u_packet_info
{
    struct nlmsghdr hdr;
    char msg[MSG_LEN];
};

int main(int argc, char* argv[])
{
    struct policy_buf data;
    struct sockaddr_nl local;
    struct sockaddr_nl kpeer;
    int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *message;
    struct u_packet_info info;
    char *retval;
    message = (struct nlmsghdr *)malloc(sizeof(struct nlmsghdr)+NLMSG_SPACE(sizeof(struct policy_buf)));

    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0){
        printf("bind() error\n");
        return -1;
    }
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 0;

    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(sizeof(struct policy_buf));
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = local.nl_pid;

    memset(&data , '\0' ,sizeof(struct policy_buf));
    //js
    strcpy(data.js , "src=\"js test\"");
    data.cmd = 0x01;
    data.js_rate=98;//98%
    //cpc
    data.cmd = data.cmd|0x02;
    data.cpc_rate=100;//100%
    data.cpc_num=1;
    data.cpc[1].is_add=1;
    strcpy(data.cpc[0].cpc_replace.src , "tieba.baidu.com");
    strcpy(data.cpc[0].cpc_replace.dst, "from=1009647e");
    //url replace
    data.cmd = data.cmd|0x04;
    data.page_url_num=1;
    strcpy(data.page_url[0].src , "www.youku.com");
    strcpy(data.page_url[0].filter, "test");
    strcpy(data.page_url[0].dst , "www.baidu.com");
    //download replace
    data.cmd = data.cmd|0x08;
    data.download_url_num=1;
    strcpy(data.download_url[0].src , "www.sohu.com");
    strcpy(data.download_url[0].filter, "test");
    strcpy(data.download_url[0].dst , "www.openinfosecfoundation.org/download/suricata-1.3.3.tar.gz");
    
    retval = memcpy(NLMSG_DATA(message), &data, sizeof(struct policy_buf));

    printf("message sendto kernel are:%s, len:%d\n", (char *)NLMSG_DATA(message), message->nlmsg_len);
    ret = sendto(skfd, message, message->nlmsg_len, 0,(struct sockaddr *)&kpeer, sizeof(kpeer));
    if(!ret){
        perror("send pid:");
        exit(-1);
    }

    ret = recvfrom(skfd, &info, sizeof(struct u_packet_info),0, (struct sockaddr*)&kpeer, &kpeerlen);
    if(!ret){
        perror("recv form kerner:");
        exit(-1);
    }

    printf("message receive from kernel:%s\n",(char *)info.msg);
    close(skfd);
    return 0;
}
