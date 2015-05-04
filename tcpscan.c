#define _BSD_SOURCE 1
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <libnet.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <pthread.h>

static u_int32_t s_src_ipaddr;        /* ip address of this host */
static libnet_t *s_netctx;            /* libnet context */
static int* s_ports;
static int s_port_num = 0;
static int s_port_scanned;
static u_int32_t s_ipaddr_begin;        /* ip address to scan */
static u_int32_t s_ipaddr_end;
static u_int32_t s_total_ip;
static u_int32_t s_open_port = 0;
static u_int32_t s_closed_port = 0;
static u_int32_t s_sent_failed = 0;
static int s_send_syn_thread_quit = 0;
static unsigned int s_interval_us = 0;
static unsigned int s_max_wait_time = 5;
static int s_netprefix_length = 0;
static u_int32_t TCP_ISN = 0;
static const char* s_user_specified_device = NULL;
static const char* s_device_name;
static int s_gateway_macaddr_set = 0;
static int s_netctx_gateway_macaddr_set = 0;
static uint8_t s_gateway_macaddr[6];
static libnet_ptag_t s_tcpopt = 0, s_tcp = 0, s_ipv4 = 0, s_ether = 0;    /* libnet protocol blocks */
static uint8_t* s_src_macaddr = 0;

static void usage()
{
    printf("tcpscan - SYN scan\n");
    printf("Usage: tcpscan [-p Port1[, Port2[, ..., PortN]]]\n"
           "              [-i ifname] [-t Timeout]\n"
           "              [-u usInterval]\n"
           "              IP[/PrefixLength]\n"
           "Example: tcpscan -p80,443 -ieth0 192.168.1.0/24\n");
}

static void init_task(char* str_ip)
{
    char* p_slash = NULL;
    in_addr_t ipaddr;
    int i;
    if ((p_slash = strchr(str_ip, '/')) != NULL)
    {
        u_int32_t netmask = 0xffffffff;
        s_netprefix_length = atoi(p_slash+1);
        char netprefix[16];
        if (!s_netprefix_length)
        {
            exit(1);
        }
        memset(netprefix, 0, 16);
        strncpy(netprefix, str_ip, p_slash - str_ip);
        if ((ipaddr = libnet_name2addr4(s_netctx, netprefix, LIBNET_RESOLVE)) == -1)
        {
            fprintf(stderr, "Invalid address: %s(%s)\n", libnet_geterror(s_netctx), netprefix);
            exit(1);
        }
        netmask &= ~1;
        for (i = 1; i < 32-s_netprefix_length; ++i)
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
        if ((ipaddr = libnet_name2addr4(s_netctx, str_ip, LIBNET_RESOLVE)) == -1)
        {
            fprintf(stderr, "Invalid address: %s(%s)\n", libnet_geterror(s_netctx), str_ip);
            exit(1);
        }
        s_ipaddr_begin = ntohl(ipaddr);
        s_ipaddr_end = s_ipaddr_begin;
        s_total_ip = 1;
    }
}

static u_int32_t get_ip(u_int32_t index)
{
    u_int32_t x = 0;
    int i;
    // reverse bits of index
    int n = 32 - s_netprefix_length;
    for (i = 0; i < n; ++i)
    {
        x |= ((index & (0x01 << i)) >> i) << (n-i-1);
    }
    return s_ipaddr_begin | x;
}

static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct tcphdr *tcp = (struct tcphdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
    struct ip *ip = (struct ip *) (packet + LIBNET_ETH_H);
    struct ether_header* ether = (struct ether_header*) packet;

    if (!s_gateway_macaddr_set)
    {
        char macaddr_str[20];
        sprintf(macaddr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            ether->ether_shost[0],
            ether->ether_shost[1],
            ether->ether_shost[2],
            ether->ether_shost[3],
            ether->ether_shost[4],
            ether->ether_shost[5]);
        printf("Gateway MAC addr: %s\n", macaddr_str);
        memcpy(s_gateway_macaddr, ether->ether_shost, 6);
        s_gateway_macaddr_set = 1;
    }

    if (tcp->th_flags == (TH_ACK | TH_RST)) //TODO: We need to consider the 'spliting handshake'
    {
        ++s_closed_port;
        printf("- %s:%d\n", libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE), ntohs(tcp->th_sport));
    }
    else if (tcp->th_flags == (TH_ACK | TH_SYN))
    {
        ++s_open_port;
        printf("+ %s:%d\n", libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE), ntohs(tcp->th_sport));
    }
    else
    {
        printf("* %s:%d\n", libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE), ntohs(tcp->th_sport));
    }
}

static void send_syn(in_addr_t src_ipaddr, int src_port, in_addr_t dst_ipaddr, int dst_port)
{
    unsigned char mss_opt[5] = {0x02,0x04,0x05,0xb4,0x00};
    s_tcpopt = libnet_build_tcp_options(mss_opt,
        4,
        s_netctx,
        s_tcpopt);

    if (s_tcpopt == -1)
    {
        fprintf(stderr, "Unable to build TCP options: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    /* build the TCP header */
    s_tcp = libnet_build_tcp (src_port,    /* src port */
        dst_port,    /* destination port */
        TCP_ISN,    /* sequence number */
        0,    /* acknowledgement */
        TH_SYN,    /* control flags */
        1024,    /* window */
        0,    /* checksum - 0 = autofill */
        0,    /* urgent */
        LIBNET_TCP_H,    /* header length */
        NULL,    /* payload */
        0,    /* payload length */
        s_netctx,    /* libnet context */
        s_tcp);    /* protocol tag */

    if (s_tcp == -1)
    {
        fprintf(stderr, "Unable to build TCP header: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    /* build the IP header */
    s_ipv4 = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H + 4,    /* length */
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
        s_ipv4);    /* protocol tag */

    if (s_ipv4 == -1)
    {
        fprintf(stderr, "Unable to build IPv4 header: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }
    
    if (s_netctx_gateway_macaddr_set)
    {
        //printf("ether\n");
        s_ether = libnet_build_ethernet(s_gateway_macaddr,
            s_src_macaddr,
            ETHERTYPE_IP,
            NULL,
            0,
            s_netctx,
            s_ether);
            
        if (s_ether == -1)
        {
            fprintf(stderr, "Unable to build Ether header: %s\n", libnet_geterror(s_netctx));
            exit(1);
        }
    }

    /* write the packet */
    if ((libnet_write(s_netctx)) == -1)
    {
        ++s_sent_failed;
    }

    //libnet_clear_packet(s_netctx);
}

static void init_net_context(int inj_type)
{
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];    /* libnet error messages */
    s_tcpopt = 0;
    s_tcp = 0;
    s_ipv4 = 0;
    s_ether = 0;
    
    s_netctx = libnet_init(inj_type, s_user_specified_device, libnet_errbuf);
    if (s_netctx == NULL)
    {
        fprintf(stderr, "Error opening context (device: %s): %s\n", s_device_name, libnet_errbuf);
        exit (1);
    }
    libnet_seed_prand(s_netctx);

    /* get the ip address of the device */
    if ((s_src_ipaddr = libnet_get_ipaddr4(s_netctx)) == -1)
    {
        fprintf (stderr, "Error getting IP: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    /* get the device we are using for libpcap */
    if ((s_device_name = libnet_getdevice(s_netctx)) == NULL)
    {
        fprintf(stderr, "Device is NULL. Packet capture may be broken\n");
    }
    
    if ((s_src_macaddr = (uint8_t*)libnet_get_hwaddr(s_netctx)) == NULL)
    {
        fprintf(stderr, "Get device MAC address error: %s", libnet_geterror(s_netctx));
    }
}

static void *send_thread(void *arg)
{
    int p;
    u_int32_t i;
    /* wait a while to make sure the main thread is ready to receive */
    usleep(10000);

    for (p = 0; p < s_port_num; ++p)
    {
        for ( i = 0; i < s_total_ip; ++i)
        {
            if (!s_netctx_gateway_macaddr_set && s_gateway_macaddr_set)
            {
                libnet_destroy(s_netctx);
                init_net_context(LIBNET_LINK);
                s_netctx_gateway_macaddr_set = 1;
            }
            send_syn(s_src_ipaddr, 
                    libnet_get_prand(LIBNET_PRu16), 
                    htonl(get_ip(i)), 
                    s_ports[p]);
            if (s_interval_us)
                usleep(s_interval_us);
        }
    }

    /* wait a while before quit */
    if (s_port_num * s_total_ip > s_open_port + s_closed_port)
        sleep(s_max_wait_time);
    s_send_syn_thread_quit = 1;
    return NULL;
}

int main (int argc, char *argv[])
{
    //const char *device = NULL;        /* device for sniffing/sending */
    char o;            /* for option processing */
    char libpcap_errbuf[PCAP_ERRBUF_SIZE];    /* pcap error messages */
    pcap_t *handle;        /* libpcap handle */
    bpf_u_int32 netp, maskp;    /* netmask and ip */
    char filter[256];
    struct bpf_program fp;    /* compiled filter */
    time_t tv;
    int i;
    
    while ((o = getopt(argc, argv, "u:i:t:p:")) > 0)
    {
        switch (o)
        {
            case 'i':
            {
                s_user_specified_device = optarg;
                break;
            }
            case 't':
            {
                s_max_wait_time = atoi(optarg);
                break;
            }
            case 'u':
            {
                s_interval_us = atoi(optarg);
                break;
            }
            case 'p':
            {
                char* p = NULL;
                char* optarg_copy = strdup(optarg);

                if (strlen(optarg_copy) > 0)
                    s_port_num = 1;

                for (p = optarg_copy; *p != '\0'; ++p)
                {
                    if (*p == ',')
                    {
                        ++s_port_num;
                    }
                }
                int i = 0;
                s_ports = (int*) malloc(s_port_num * (sizeof (int)));
                while ((p = strsep(&optarg_copy, ",")) != NULL)
                {
                    int temp = atoi(p);
                    if (!temp)
                    {
                        printf("Illegal port: %s\n", p);
                        usage();
                        exit(1);
                    }
                    s_ports[i++] = temp;
                }
                free(optarg_copy);
                break;
            }
            case '?':
            {
                printf("Unkown option: %c\n", optopt);
                break;
            }
            default:
            {
                usage();
                exit(1);
                break;
            }
        }
    }

    if (argc != optind + 1)
    {
        usage();
        exit(1);
    }

    if (geteuid())
    {
        fprintf(stderr, "Please run as root privileges.\n");
        exit(1);
    }

    if (s_port_num == 0)
    {
        int default_ports[] = {21, 22, 23, 80, 110, 443};
        s_port_num = (sizeof default_ports) / (sizeof (int));
        s_ports = (int*) malloc(s_port_num * (sizeof (int)));
        for (i = 0; i < s_port_num; ++i)
        {
            s_ports[i] = default_ports[i];
        }
    }

    TCP_ISN = libnet_get_prand(LIBNET_PRu32);
    init_net_context(LIBNET_RAW4);
    init_task(argv[optind]);
    snprintf(filter, sizeof filter, "(dst host %s) && tcp[8:4] == %d", libnet_addr2name4(s_src_ipaddr, LIBNET_DONT_RESOLVE), TCP_ISN + 1);
    printf("Device: %s, IP: %s\n", s_device_name, libnet_addr2name4(s_src_ipaddr, LIBNET_DONT_RESOLVE));

    /* open the device with pcap */
    if ((handle = pcap_open_live(s_device_name, 1500, 0, 2000, libpcap_errbuf)) == NULL)
    {
        fprintf(stderr, "Error opening pcap: %s\n", libpcap_errbuf);
        exit(1);
    }
    if ((pcap_setnonblock(handle, 1, libpcap_errbuf)) == -1)
    {
        fprintf(stderr, "Error setting nonblocking: %s\n", libpcap_errbuf);
        exit(1);
    }
    if (pcap_lookupnet(s_device_name, &netp, &maskp, libpcap_errbuf) == -1)
    {
        fprintf(stderr, "Net lookup error: %s\n", libpcap_errbuf);
        exit(1);
    }
    if (pcap_compile(handle, &fp, filter, 0, maskp) == -1)
    {
        fprintf(stderr, "BPF error: %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error setting BPF: %s\n", pcap_geterr(handle));
        exit(1);
    }

    pcap_freecode(&fp);
    s_port_scanned = 0;
    printf("%s-%s Total: %d\n",
        libnet_addr2name4(htonl(s_ipaddr_begin), LIBNET_DONT_RESOLVE),
        libnet_addr2name4(htonl(s_ipaddr_end), LIBNET_DONT_RESOLVE),
        s_total_ip);

    pthread_t ntid;
    pthread_create(&ntid, NULL, send_thread, NULL);

    while (s_port_scanned < s_port_num * s_total_ip)
    {
        int ret = pcap_dispatch(handle, 10, packet_handler, NULL);
        if (ret > 0)
            s_port_scanned += ret;
        if (s_send_syn_thread_quit)
        {
            break;
        }
    }
    printf("Open: %d, Closed: %d, Failed: %d\n", s_open_port, s_closed_port, s_sent_failed);
    pcap_close(handle);
    libnet_destroy(s_netctx);
    if (s_ports)
        free(s_ports);
    return 0;
}
