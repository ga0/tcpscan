#include <libnet.h>
#include "net_context.h"

static libnet_t *s_netctx;            /* libnet context */
static u_int32_t s_sent_failed = 0;
static int s_send_syn_thread_quit = 0;
static u_int32_t s_ipaddr_begin;        /* ip address to scan */
static u_int32_t s_ipaddr_end;
static int s_netprefix_length = 0;
static unsigned int s_interval_us = 1000;
static u_int32_t s_open_port = 0;
static u_int32_t s_closed_port = 0;
static int s_gateway_macaddr_detected = 0;
static u_int32_t s_total_ip;
static u_int32_t s_src_ipaddr;        /* ip address of this host */
static u_int32_t s_isn;

static u_int32_t get_ip(u_int32_t index)
{
    u_int32_t x = 0;
    /* reverse bits of index */
    int n = 32 - s_netprefix_length;
    for (int i = 0; i < n; ++i)
    {
        x |= ((index & (0x01 << i)) >> i) << (n-i-1);
    }
    return s_ipaddr_begin | x;
}

static void send_syn(in_addr_t src_ipaddr, int src_port, in_addr_t dst_ipaddr, int dst_port)
{
    libnet_ptag_t tcp = 0, ipv4 = 0, ether = 0;    /* libnet protocol blocks */

    unsigned char mss_opt[5] = {0x02,0x04,0x05,0xb4,0x00};
    tcp = libnet_build_tcp_options(mss_opt,
        4,
        s_netctx,
        0);

    if (tcp == -1)
    {
        fprintf(stderr, "Unable to build TCP options: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    /* build the TCP header */
    tcp = libnet_build_tcp (src_port,    /* src port */
        dst_port,    /* destination port */
        s_isn,    /* sequence number */
        0,    /* acknowledgement */
        TH_SYN,    /* control flags */
        1024,    /* window */
        0,    /* checksum - 0 = autofill */
        0,    /* urgent */
        LIBNET_TCP_H,    /* header length */
        NULL,    /* payload */
        0,    /* payload length */
        s_netctx,    /* libnet context */
        0);    /* protocol tag */

    if (tcp == -1)
    {
        fprintf(stderr, "Unable to build TCP header: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    /* build the IP header */
    ipv4 = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H + 4,    /* length */
        0,    /* TOS */
        libnet_get_prand(LIBNET_PRu16),    /* IP ID */
        0,    /* frag offset */
        127,    /* TTL */
        IPPROTO_TCP,    /* upper layer protocol */
        0,    /* checksum, 0=autofill */
        src_ipaddr,    /* src IP */
        dst_ipaddr,    /* dest IP */
        NULL,    /* payload */
        0,    /* payload len */
        s_netctx,    /* libnet context */
        0);    /* protocol tag */

    if (ipv4 == -1)
    {
        fprintf(stderr, "Unable to build IPv4 header: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }
    
    /*if (s_gateway_macaddr_detected)
    {
        ether = libnet_autobuild_ethernet((uint8_t*)s_gateway_macaddr_str,
            ETHERTYPE_IP,
            s_netctx);
        
        if (ether == -1)
        {
            fprintf(stderr, "Unable to build Ether header: %s\n", libnet_geterror(s_netctx));
            exit(1);
        }
    }*/

    /* write the packet */
    if ((libnet_write(s_netctx)) == -1)
    {
        ++s_sent_failed;
    }

    libnet_clear_packet(s_netctx);
}

void *send_thread(void *arg)
{
    /* wait a while to make sure the main thread is ready to receive */
    usleep(10000);

    for (int p = 0; p < s_port_num; ++p)
    {
        for (u_int32_t i = 0; i < s_total_ip; ++i)
        {
            send_syn(s_src_ipaddr, 
                    libnet_get_prand(LIBNET_PRu16), 
                    htonl(get_ip(i)), 
                    s_ports[p]);
            if (s_interval_us)
                usleep(s_interval_us);
        }
    }

    /* wait a while before quit */
   /* if (s_port_num * s_total_ip > s_open_port + s_closed_port)
        sleep(s_max_wait_time);*/
    s_send_syn_thread_quit = 1;
    return NULL;
}

static void parse_cidr(const char* cidr)
{
    char* p_slash = NULL;
    in_addr_t ipaddr;
    if ((p_slash = strchr(cidr, '/')) != NULL)
    {
        u_int32_t netmask = 0xffffffff;
        s_netprefix_length = atoi(p_slash+1);
        char netprefix[16];
        if (!s_netprefix_length)
        {
            exit(1);
        }
        memset(netprefix, 0, 16);
        strncpy(netprefix, cidr, p_slash - cidr);
        if ((ipaddr = libnet_name2addr4(s_netctx, netprefix, LIBNET_RESOLVE)) == -1)
        {
            fprintf(stderr, "Invalid address: %s(%s)\n", libnet_geterror(s_netctx), netprefix);
            exit(1);
        }
        netmask &= ~1;
        for (int i = 1; i < 32-s_netprefix_length; ++i)
        {
            netmask <<= 1;
            netmask &= ~1;
        }
        s_ipaddr_begin = ntohl(ipaddr) & netmask;
        s_ipaddr_end = s_ipaddr_begin | ~netmask;
        s_total_ip = s_ipaddr_end - s_ipaddr_begin + 1;
    }
    else
    {
        if ((ipaddr = libnet_name2addr4(s_netctx, cidr, LIBNET_RESOLVE)) == -1)
        {
            fprintf(stderr, "Invalid address: %s(%s)\n", libnet_geterror(s_netctx), cidr);
            exit(1);
        }
        s_ipaddr_begin = ntohl(ipaddr);
        s_ipaddr_end = s_ipaddr_begin;
        s_total_ip = 1;
    }
}

void init_net_context(const char* device, const char* cidr, u_int32_t isn)
{
    s_isn = isn;
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];    /* libnet error messages */
    
    s_netctx = libnet_init(LIBNET_RAW4, device, libnet_errbuf);
    if (s_netctx == NULL)
    {
        fprintf(stderr, "Error opening context: %s\n", libnet_errbuf);
        exit (1);
    }
    libnet_seed_prand(s_netctx);
    
    /* get the ip address of the device */
    if ((s_src_ipaddr = libnet_get_ipaddr4(s_netctx)) == -1)
    {
        fprintf (stderr, "Error getting IP: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }
    
    parse_cidr(cidr);
}

