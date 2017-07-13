#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>


pcap_t *p;

#define IPv4 0x800
#define ARP 0x806

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

int main(int argc, char **argv) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	printf("Device: %s\n", dev);
    p = pcap_open_live(dev, 16384, 1, 200, errbuf);

	if (p == NULL) {
		fprintf(stderr, "Couldn't open pcap: %s\n", errbuf);
		return(2);
	}

    printf("p -> %p\n", p);

    pcap_loop(p, -1, got_packet, NULL); // sniff until error occurs

    pcap_close(p);
    p = NULL;

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet) {

    // eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data

    // printf("caplen: %u, len: %u\n", header->caplen, header->len);

    int hIdx = 0;
    char type[2] = {0, 0};
    unsigned short ether_type;

    puts("\x1B[32m========== New Packet ==========\x1B[0m");

    printf("\x1B[36mdest mac -> %02X:%02X:%02X:%02X:%02X:%02X\n", packet[hIdx++], 
            packet[hIdx++], packet[hIdx++], packet[hIdx++], packet[hIdx++], packet[hIdx++]);
    
    printf("\x1B[31msrc mac  -> %02X:%02X:%02X:%02X:%02X:%02X\n", packet[hIdx++], 
            packet[hIdx++], packet[hIdx++], packet[hIdx++], packet[hIdx++], packet[hIdx++]);

    type[0] = packet[hIdx++];
    type[1] = packet[hIdx++];

    ether_type = ntohs(*(unsigned short *)type);

    if (ether_type == IPv4) {
        printf("\x1B[93mether type ->  %#04x IPv4\n", ether_type);
    } else if (ether_type == ARP) {
        printf("\x1B[93mether type ->  %#04x ARP\n", ether_type);
    } else {
        printf("\x1B[93mether type ->  %#04x Do Not Implemented\n", ether_type);
    }

    hIdx += 8;

    printf("\x1B[35mttl: %u\n", packet[hIdx]);
    printf("\x1B[95mprotocol: %u\n", packet[hIdx+1]);

    hIdx += 4;
    printf("\x1B[31msrc ip  -> %u.%u.%u.%u\n", packet[hIdx], packet[hIdx+1], packet[hIdx+2], packet[hIdx+3]);
    hIdx += 4;
    printf("\x1B[36mdest ip -> %u.%u.%u.%u\n", packet[hIdx], packet[hIdx+1], packet[hIdx+2], packet[hIdx+3]);

}

