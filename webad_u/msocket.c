  
#include "msocket.h"
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

static int socktfd=0;
static pthread_mutex_t skmutex=PTHREAD_MUTEX_INITIALIZER;

void close_socket()
{
    pthread_mutex_lock(&skmutex);
    if(socktfd)
    {
        close(socktfd);
		socktfd=0;
    } 
	pthread_mutex_unlock(&skmutex);
}

int open_socket(char* ip , int port)
{
	struct timeval tv;
	struct sockaddr_in addr;
	if(socktfd)
    {
        close_socket();
    } 
    
	pthread_mutex_lock(&skmutex);
	if((socktfd=socket(AF_INET , SOCK_STREAM , 0))<0){
	        perror("socket error");
			pthread_mutex_unlock(&skmutex);
	        return -1;
	}

	if(!strlen(ip)||!port)
	{
		pthread_mutex_unlock(&skmutex);
		return -1;
	}

	bzero(&addr,sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr= inet_addr(ip);
	addr.sin_port=htons(port);

	if(connect(socktfd,(struct sockaddr*)&addr,sizeof(struct sockaddr_in))<0)
	{
	        perror("socket connect error");
			close(socktfd);
			socktfd=0;
			pthread_mutex_unlock(&skmutex);
	        return -1;
	}

	tv.tv_sec  = 5;
	tv.tv_usec = 0; 

	if(setsockopt(socktfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval))<0)
	{

		perror("socket setsockopt error");
		pthread_mutex_unlock(&skmutex);
		return -1;
	}

	if(setsockopt(socktfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval))<0)
	{
		perror("socket setsockopt error");
		pthread_mutex_unlock(&skmutex);
		return -1;
	}
	pthread_mutex_unlock(&skmutex);
	return socktfd;
}

int send_data(void* data , int len)
{
	int totle_len,tmp_len;
	pthread_mutex_lock(&skmutex);
	if(!socktfd)
    {
    	pthread_mutex_unlock(&skmutex);
    	return -1;
	}
	if((totle_len=send(socktfd,data,len,0))<=0)
	{
		perror("socket send error");
		pthread_mutex_unlock(&skmutex);
		return -1;
	}
	while(totle_len<len)
	{
		tmp_len=send(socktfd,data+totle_len,len-totle_len,0);
		if (tmp_len <= 0)
		{
			pthread_mutex_unlock(&skmutex);
			return -1;
		}
		totle_len+=tmp_len;
	}

	pthread_mutex_unlock(&skmutex);
	return totle_len;
	
}

int recv_data(void* data , int max_len)
{
	int totle_len;
	pthread_mutex_lock(&skmutex);
	if(!socktfd)
    {
    	pthread_mutex_unlock(&skmutex);
    	return -1;
	}
	if((totle_len=recv(socktfd,data,max_len,0))<=0)
	{
		perror("socket recv error");
		pthread_mutex_unlock(&skmutex);
		return -1;
	}
	pthread_mutex_unlock(&skmutex);
	return totle_len;
	
}

int is_connect()
{
	int ret;
	struct timeval tv;
	fd_set fds;

	pthread_mutex_lock(&skmutex);
	if(!socktfd)
    {
    	pthread_mutex_unlock(&skmutex);
    	return -1;
	}
	FD_ZERO(&fds);
	FD_SET(socktfd,&fds);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	ret = select(socktfd+1,NULL,&fds,NULL,&tv);
	pthread_mutex_unlock(&skmutex);
	return ret;
}

