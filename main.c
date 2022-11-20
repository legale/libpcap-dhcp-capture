#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

/* cli arguments parse macro and functions */
#define NEXT_ARG() do { argv++; if (--argc <= 0) incomplete_command(); } while(0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREV_ARG() do { argv--; argc++; } while(0)



/*
 * an IPv4 address from a packet data buffer; it was introduced in reaction
 * to somebody who *had* done that.
 */
typedef unsigned char nd_ipv4[4];

/*
 * Use this for blobs of bytes; make them arrays of nd_byte.
 */
typedef unsigned char nd_byte;

/*
 * Data types corresponding to multi-byte integral values within data
 * structures.  These are defined as arrays of octets, so that they're
 * not aligned on their "natural" boundaries, and so that you *must*
 * use the EXTRACT_ macros to extract them (which you should be doing
 * *anyway*, so as not to assume a particular byte order or alignment
 * in your code).
 *
 * We even want EXTRACT_U_1 used for 8-bit integral values, so we
 * define nd_uint8_t and nd_int8_t as arrays as well.
 */
typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint24_t[3];
typedef unsigned char nd_uint32_t[4];
typedef unsigned char nd_uint40_t[5];
typedef unsigned char nd_uint48_t[6];
typedef unsigned char nd_uint56_t[7];
typedef unsigned char nd_uint64_t[8];

typedef signed char nd_int8_t[1];

/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

struct bootp {
	nd_uint8_t	bp_op;		/* packet opcode type */
	nd_uint8_t	bp_htype;	/* hardware addr type */
	nd_uint8_t	bp_hlen;	/* hardware addr length */
	nd_uint8_t	bp_hops;	/* gateway hops */
	nd_uint32_t	bp_xid;		/* transaction ID */
	nd_uint16_t	bp_secs;	/* seconds since boot began */
	nd_uint16_t	bp_flags;	/* flags - see bootp_flag_values[]
					   in print-bootp.c */
	nd_ipv4		bp_ciaddr;	/* client IP address */
	nd_ipv4		bp_yiaddr;	/* 'your' IP address */
	nd_ipv4		bp_siaddr;	/* server IP address */
	nd_ipv4		bp_giaddr;	/* gateway IP address */
	nd_byte		bp_chaddr[16];	/* client hardware address */
	nd_byte		bp_sname[64];	/* server host name */
	nd_byte		bp_file[128];	/* boot file name */
	nd_byte		bp_vend[64];	/* vendor-specific area */
};


/**
 * 
 * 
 * 
*/
struct vlan_header
{
  uint16_t ether_type;		        /* packet type ID field	*/
  uint16_t vlanid;		        /* packet type ID field	*/
} __attribute__ ((__packed__));

#define BOOTPREPLY	2
#define BOOTPREQUEST	1
#define TOKBUFSIZE 128
struct tok {
	u_int v;		/* value */
	const char *s;		/* string */
};

static const struct tok bootp_op_values[] = {
	{ BOOTPREQUEST,	"Request" },
	{ BOOTPREPLY,	"Reply" },
	{ 0, NULL}
};

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
static const char *
tok2strbuf(const struct tok *lp, const char *fmt,
	   const u_int v, char *buf, const size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}


/*
 * Convert a token value to a string; use "fmt" if not found.
 * Uses tok2strbuf() on one of four local static buffers of size TOKBUFSIZE
 * in round-robin fashion.
 */
const char *
tok2str(const struct tok *lp, const char *fmt, const u_int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}


static void incomplete_command(void) {
    fprintf(stderr, "Command line is not complete. Try -h or --help\n");
    exit(-1);
}

static char *argv0; /* ptr to the program name string */
static void usage(void) {
    fprintf(stdout,
            "Usage:   %s {INTERFACE}  \n"
            "\n"
            "Example: %s eth0           \n"
            "\n", argv0, argv0);
    exit(-1);
}

/* Returns true if 'prefix' is a not empty prefix of 'string'. */
static bool matches(const char *prefix, const char *string) {
    if (!*prefix)
        return false;
    while (*string && *prefix == *string) {
        prefix++;
        string++;
    }
    return !*prefix;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header,
    const u_char *payload);


    /* 
    * First we will check the packet size. 
    * We need only server to client packets.
    * All messages from the server (as opposed to the client) 
    * also MUST include a Server Identifier option (6 bytes).  
    * 236 + 4 + 3 + 1 + 6 = 250.
    * ethernet header length    - 14 bytes
    * ip header length     - 20-24 bytes
    * udp header length         - 8 bytes
    * 250 + 14 + 20 + 8 = 292 bytes
    * 
    * BOOTP packet structure
    * http://www.faqs.org/rfcs/rfc2131.html
    * 0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
    */


int main(int argc, char *argv[]) {
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const int buf_size = 512; /* interested packet size range 292 - 512 */
    int timeout_limit = 10000; /* In milliseconds */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "len >= 292 && !ip broadcast && udp && port 68";	/* The filter expression catch only dhcp ack from serv to cli                */
    //bpf_u_int32 mask = 0;		/* Our netmask */
	bpf_u_int32 net = 0;		/* Our IP */

    /* cli arguments parse */
    argv0 = *argv; /* set program name */
    if (argc == 1) usage();
    while (argc > 1) {
        NEXT_ARG();
        if (matches(*argv, "-h")) {
            usage();
        } else if (matches(*argv, "--help")) {
            usage();
        } else if (!matches(*argv, "-")) {
            device = *argv;
        } else {
            usage();
        }
        argc--;
        argv++;
    }


    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            buf_size, /* inplace BUFSIZ 8192 */
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
     }

     /* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
     
    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *h, /* header */
    const u_char *p /* packet body */
)
{
    /* Pointers to start point of various headers */
    const u_char *ip_h;
    const u_char *udp_h;
    const u_char *payload;

    /* Header lengths in bytes */
    struct ether_header *eth_h = (struct ether_header *) p;
    int ethernet_h_len = 14; /* depends on ethernet type */

    /* if we have got 802.1Q frame */
    uint16_t *ether_type = &eth_h->ether_type;
    int cnt = 0;
    while(ntohs(*ether_type) == ETHERTYPE_VLAN){
        if(cnt++ > 2){
            printf("error: vlan headers > 2\n");
        }
        struct vlan_header *vlan_h = eth_h;
        printf("VLAN ID 0x%02X\n", ntohs(vlan_h->vlanid));
        ethernet_h_len += 4; 
        ether_type += 4;
    }
    printf("ether_type 0x%02X\n", ntohs(*ether_type));
    
    int ip_h_len;
    int udp_len;
    const int udp_h_len = 8; /* fixed size 8 bytes */
    int payload_len;


    /* Find start of IP header */
    ip_h = p + ethernet_h_len;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_h_len = ((*ip_h) & 0x0F);
    ip_h_len = ip_h_len * 4;

    int total_headers_size = ethernet_h_len + ip_h_len + udp_h_len;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
        if(total_headers_size > h->caplen){
        printf("Total headers size (%d) > packet captured size (%d). Skipping...\n", total_headers_size, h->caplen);
        return;
    }

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is UDP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = ip_h[9];
    if (protocol != IPPROTO_UDP) {
        printf("%d Not a UDP packet. Skipping...\n", protocol);
        return;
    }
    
    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the UDP header */
    udp_h = p + ethernet_h_len + ip_h_len;
    /* The UDP header length is fixed size 8 bytes. Structure:
    | src port 2B | dst port 2B | len 2B | checksum 2B | 
    packet data is little endian (aka network order), so for big endian system we need to
    swap data bytes
    */
    udp_len = ntohs(*(uint16_t *)(udp_h + 4));
    printf("UDP header + data length in bytes: %d\n", udp_len);

    /* Find the payload offset */
    payload_len = h->caplen -
        (ethernet_h_len + ip_h_len + udp_h_len);
    printf("Payload size: %d bytes\n", payload_len);
    payload = p + total_headers_size;
    if(payload_len < sizeof(struct bootp)){
        printf("payload size(%d) < bootp structure size(%lu). Skipping...\n", payload_len, sizeof(struct bootp));
        return;
    }
    printf("Memory address where payload begins: %p\n", payload);


    print_packet_info(p, *h, payload);
    return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_h,
    const u_char *payload) {
    struct ether_header *eth_h;
    struct bootp *bootp = (struct bootp *)payload;
    /* check dhcp packet op code */
    if(*bootp->bp_op != BOOTPREPLY){
        return;
    }

    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_h = (struct ether_header *) packet;
    u_char *src = eth_h->ether_shost;
    u_char *dst = eth_h->ether_dhost; 
    printf("len/total: %d/%d s: %02X:%02X:%02X:%02X:%02X:%02X "
                            "d: %02X:%02X:%02X:%02X:%02X:%02X\n", 
        packet_h.caplen, 
        packet_h.len,
        src[0], src[1], src[2], src[3], src[4], src[5],
        dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]
    );
    struct in_addr *yi = (struct in_addr *)&bootp->bp_yiaddr;


    printf("%s ip: %s\n", tok2str(bootp_op_values, "unknown (0x%02x)", *bootp->bp_op), inet_ntoa(*yi));

}

