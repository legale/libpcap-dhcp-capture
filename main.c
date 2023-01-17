#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "pcap_dhcp.h"

/* cli arguments parse macro and functions */
#define NEXT_ARG() do { argv++; if (--argc <= 0) incomplete_command(); } while(0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREV_ARG() do { argv--; argc++; } while(0)


static char *argv0; /* ptr to the program name string */


static void incomplete_command(void) {
    fprintf(stderr, "Command line is not complete. Try -h or --help\n");
    exit(-1);
}

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


static const struct tok bootp_op_values[] = {
	{ BOOTPREQUEST,	"Request" },
	{ BOOTPREPLY,	"Reply" },
	{ 0, NULL}
};



static void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_h, const u_char *payload, void *user_arg) {
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
    u_char *cli = bootp->bp_chaddr; 
    printf("len/total: %d/%d src: %02X:%02X:%02X:%02X:%02X:%02X "
                            "dst: %02X:%02X:%02X:%02X:%02X:%02X "
                            "cli: %02X:%02X:%02X:%02X:%02X:%02X\n", 
        packet_h.caplen, 
        packet_h.len,
        src[0], src[1], src[2], src[3], src[4], src[5],
        dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
        cli[0], cli[1], cli[2], cli[3], cli[4], cli[5]
    );
    struct in_addr *yi = (struct in_addr *)&bootp->bp_yiaddr;


    printf("%s ip: %s\n", tok2str(bootp_op_values, "unknown (0x%02x)", *bootp->bp_op), inet_ntoa(*yi));
    
}


int main(int argc, char *argv[]) {
    char *device = NULL;

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


    pcap_t *handle = dhcp_pcap_open_live(device);


    pcap_dhcp_user_s user = {
        .callback = &print_packet_info,
        .callback_arg = NULL}; /* here you can pass additional arg to callback function */
    if(handle != NULL){
        pcap_loop(handle, 0, dhcp_packet_handler, (u_char *)&user);
    }else{
        return 1;
    }
    return 0;
}

