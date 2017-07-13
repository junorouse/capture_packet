#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>


pcap_t *p;

void DumpHex(const void* data, unsigned int size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
        u_int ip_src;
        u_int ip_dst;
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;



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
    char tcp_seq_[4] = {0, 0, 0, 0};
    unsigned int tcp_seq;
    unsigned short ether_type, sport, dport;

    ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		// printf("\x1B[96m* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		// printf("\x1B[96m* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    puts("\x1B[32m============== Packet ==============\x1B[0m");

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
    hIdx += 4;

    type[0] = packet[hIdx++];
    type[1] = packet[hIdx++];

    sport = ntohs(*(unsigned short *)type);
    printf("\x1B[31msport: %u\n", sport);

    type[0] = packet[hIdx++];
    type[1] = packet[hIdx++];

    dport = ntohs(*(unsigned short *)type);
    printf("\x1B[36mdport: %u\n", dport);

    tcp_seq_[3] = packet[hIdx++];
    tcp_seq_[2] = packet[hIdx++];
    tcp_seq_[1] = packet[hIdx++];
    tcp_seq_[0] = packet[hIdx++];

    tcp_seq = *(unsigned int *)tcp_seq_; // big endian
    printf("\x1B[92mtcp_seq -> %u\n", tcp_seq);

    hIdx += 4;

    // puts(payload);
    printf("\x1B[34mcap len: %d\n", header->caplen);
    printf("header len: %d\n\x1B[37m", SIZE_ETHERNET + size_ip + size_tcp);
    int realSize = header->caplen - (SIZE_ETHERNET + size_ip + size_tcp);
    if (!(realSize <= 0))
        DumpHex(payload, header->caplen);


}

