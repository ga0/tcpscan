#ifndef __NET_CONTEXT_H__
#define __NET_CONTEXT_H__

void *send_thread(void *arg);
void init_net_context(const char* device, const char* cidr, u_int32_t isn);

#endif
