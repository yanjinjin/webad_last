#ifndef __MSOCKET_H__
#define __MSOCKET_H__


int open_socket(char* ip , int port);

void close_socket();

int send_data(void* data , int len);

int recv_data(void* data , int max_len);

int is_connect();

#endif 
