#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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
    if(handle != NULL){
        pcap_loop(handle, 0, dhcp_packet_handler, NULL);
    }else{
        return 1;
    }
    return 0;
}

