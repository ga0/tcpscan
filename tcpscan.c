#define _BSD_SOURCE 1
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <libnet.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
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
static unsigned int s_interval_us = 1000;
static unsigned int s_max_wait_time = 5;
static int s_netprefix_length = 0;
static const u_int32_t INIT_ISN = 11341;

static void usage()
{
    printf("tcpscan - SYN scan\n");
    printf("Usage: tcpscan [-p Port1[, Port2[, ..., PortN]]]\n"
           "              [-i ifname] [-t Timeout]\n"
           "              [-u usInterval]\n"
           "              IP[/PrefixLength]\n"
           "Example: tcpscan -p80,443 -ieth0 192.168.1.0/24\n");
}

static void init_task(char* strip)
{
    char* p_slash = NULL;
    in_addr_t ipaddr;
    if ((p_slash = strchr(strip, '/')) != NULL)
    {
        u_int32_t netmask = 0xffffffff;
        s_netprefix_length = atoi(p_slash+1);
        char netprefix[16];
        if (!s_netprefix_length)
        {
            exit(1);
        }
        memset(netprefix, 0, 16);
        strncpy(netprefix, strip, p_slash - strip);
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
        if ((ipaddr = libnet_name2addr4(s_netctx, strip, LIBNET_RESOLVE)) == -1)
        {
            fprintf(stderr, "Invalid address: %s(%s)\n", libnet_geterror(s_netctx), strip);
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
    /* reverse bits of index */
    int n = 32 - s_netprefix_length;
    for (int i = 0; i < n; ++i)
    {
        x |= ((index & (0x01 << i)) >> i) << (n-i-1);
    }
    return s_ipaddr_begin | x;
}

static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct tcphdr *tcp = (struct tcphdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
    struct ip *ip = (struct ip *) (packet + LIBNET_ETH_H);

    if (ntohl(tcp->th_ack) != INIT_ISN + 1)
    {
        printf("Seq error. %0x != %0x\n", ntohl(tcp->th_ack), INIT_ISN + 1);
        return;
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
    libnet_ptag_t tcp = 0, ipv4 = 0;    /* libnet protocol blocks */

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
        INIT_ISN,    /* sequence number */
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
        fprintf(stderr, "Unable to build IPv4 header: %s\n", libnet_geterror (s_netctx));
        exit(1);
    }

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
    if (s_port_num * s_total_ip > s_open_port + s_closed_port)
        sleep(s_max_wait_time);
    s_send_syn_thread_quit = 1;
    return NULL;
}

int main (int argc, char *argv[])
{
    const char *device = NULL;        /* device for sniffing/sending */
    char o;            /* for option processing */
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];    /* libnet error messages */
    char libpcap_errbuf[PCAP_ERRBUF_SIZE];    /* pcap error messages */
    pcap_t *handle;        /* libpcap handle */
    bpf_u_int32 netp, maskp;    /* netmask and ip */
    char filter[256];
    struct bpf_program fp;    /* compiled filter */
    time_t tv;

    while ((o = getopt(argc, argv, "u:i:t:p:")) > 0)
    {
        switch (o)
        {
            case 'i':
            {
                device = optarg;
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
        for (int i = 0; i < s_port_num; ++i)
        {
            s_ports[i] = default_ports[i];
        }
    }

    s_netctx = libnet_init(LIBNET_RAW4, device, libnet_errbuf);
    if (s_netctx == NULL)
    {
        fprintf(stderr, "Error opening context: %s\n", libnet_errbuf);
        exit (1);
    }
    libnet_seed_prand(s_netctx);

    init_task(argv[optind]);

    /* get the ip address of the device */
    if ((s_src_ipaddr = libnet_get_ipaddr4(s_netctx)) == -1)
    {
        fprintf (stderr, "Error getting IP: %s\n", libnet_geterror(s_netctx));
        exit(1);
    }

    snprintf(filter, sizeof filter, "(dst host %s) && tcp[8:4] == %d", libnet_addr2name4(s_src_ipaddr, LIBNET_DONT_RESOLVE), INIT_ISN + 1);

    /* get the device we are using for libpcap */
    if ((device = libnet_getdevice(s_netctx)) == NULL)
    {
        fprintf(stderr, "Device is NULL. Packet capture may be broken\n");
    }

    printf("Device: %s, IP: %s\n", device, libnet_addr2name4(s_src_ipaddr, LIBNET_DONT_RESOLVE));

    /* open the device with pcap */
    if ((handle = pcap_open_live(device, 1500, 0, 2000, libpcap_errbuf)) == NULL)
    {
        fprintf(stderr, "Error opening pcap: %s\n", libpcap_errbuf);
        exit(1);
    }
    if ((pcap_setnonblock(handle, 1, libnet_errbuf)) == -1)
    {
        fprintf(stderr, "Error setting nonblocking: %s\n", libpcap_errbuf);
        exit(1);
    }
    if (pcap_lookupnet(device, &netp, &maskp, libpcap_errbuf) == -1)
    {
        fprintf(stderr, "Net lookup error: %s\n", libpcap_errbuf);
        exit(1);
    }
    if (pcap_compile(handle, &fp, filter, 0, maskp) == -1)
    {
        fprintf(stderr, "BPF error: %s\n", pcap_geterr (handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error setting BPF: %s\n", pcap_geterr (handle));
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
        int ret = pcap_dispatch(handle, s_port_num, packet_handler, NULL);
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
