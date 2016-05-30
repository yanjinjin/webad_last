#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>

#define NETLINK_TEST 31 
static int skfd=0;

void close_netlink()
{   
    if(skfd)
    {
        close(skfd);
        skfd=0;
    }
}

int open_netlink()
{
    struct sockaddr_nl local; 
    if(skfd)
        close_netlink();
    
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
    return 0;
}


int send_to_knl(void* data ,int size)
{
    struct sockaddr_nl kpeer;
    int ret;
    struct nlmsghdr *message;
    message = (struct nlmsghdr *)malloc(sizeof(struct nlmsghdr)+NLMSG_SPACE(size));
    if(!message)
        return -1;
    
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 0;

    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(size);
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = getpid();

    memcpy(NLMSG_DATA(message), data, size);

    ret = sendto(skfd, message, message->nlmsg_len, 0,(struct sockaddr *)&kpeer, sizeof(kpeer));
    if(!ret)
    {
        perror("send pid:");
        free(message);
        return -1;
    }
    free(message);
    return ret;
    
}
