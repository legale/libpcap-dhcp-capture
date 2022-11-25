#include "pcap_dhcp.h"


/*
 * Convert a token value to a string; use "fmt" if not found.
 */
static const char *tok2strbuf(const struct tok *lp, const char *fmt, const u_int v, char *buf, const size_t bufsize){
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
const char *tok2str(const struct tok *lp, const char *fmt, const u_int v){
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

void dhcp_packet_handler(u_char *args, const struct pcap_pkthdr *h, const u_char *p){

    /* Pointers to start point of various headers */
    const u_char *ip_h;
    const u_char *udp_h;
    const u_char *payload;

    /* Header lengths in bytes */
    struct ether_header *eth_h = (struct ether_header *) p;
    int ethernet_h_len = 14; /* depends on ethernet type */

    /* if we have got 802.1Q frame */
    uint16_t *ether_type = (uint16_t *)&eth_h->ether_type;
    int cnt = 0;
    while(ntohs(*ether_type) == ETHERTYPE_VLAN){
        if(cnt++ > 2){
            printf("error: vlan headers > 2\n");
        }
        struct vlan_header *vlan_h = (struct vlan_header *)eth_h;
        printf("VLAN ID 0x%04X\n", ntohs(vlan_h->vlanid));
        ethernet_h_len += 4; 
        ether_type += 4;
    }
    printf("ether_type 0x%04X\n", ntohs(*ether_type));
    
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
        printf("payload size(%d) < bootp structure size(%u). Skipping...\n", payload_len, (uint32_t)sizeof(struct bootp));
        return;
    }
    printf("Memory address where payload begins: %p\n", payload);

    pcap_dhcp_user_s *user = (pcap_dhcp_user_s *)args;
    (*user->callback)(p, *h, payload, user->callback_arg);
    return;
}


pcap_t *dhcp_pcap_open_live(const char *device){
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const int buf_size = 512; /* interested packet size range 292 - 512 */
    int timeout_limit = 5000; /* In milliseconds */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "len >= 292 && !ip broadcast && udp && port 68";	/* The filter expression catch only dhcp ack from serv to cli                */
    //bpf_u_int32 mask = 0;		/* Our netmask */
	bpf_u_int32 net = 0;		/* Our IP */

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            buf_size, /* inplace BUFSIZ 8192 */
            1, /* promiscuous mode */
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "error: Could not open device %s: %s\n", device, error_buffer);
         return NULL;
     }
     //set nonblocking mode
     pcap_setnonblock(handle, 1, error_buffer);


     /* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
		fprintf(stderr, "error: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_close(handle);
        return NULL;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "error: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_close(handle);
        return NULL;
	}

    return handle;
}