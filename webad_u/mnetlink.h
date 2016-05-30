#ifndef __MNETLINK_H__
#define __MNETLINK_H__

void close_netlink();
int open_netlink();
int send_to_knl(void* data ,int size);

#endif 
