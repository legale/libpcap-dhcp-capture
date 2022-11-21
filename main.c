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
     
    pcap_loop(handle, 0, dhcp_packet_handler, NULL);

    return 0;
}

