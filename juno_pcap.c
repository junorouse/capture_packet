#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <libnet.h>

pcap_t *p;
#define IP_TCP 0x06

void DumpHex(const void* data, u_int64_t size) {
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

const char *get_eth_type_descr(uint16_t ethType) {
    switch (ethType) {
        case ETHERTYPE_IP: return "IPv4";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_ARP: return "ARP";
        default: return NULL;
    }
}



char *hex2mac(const uint8_t mac[6]) {
    static char str[24];
    snprintf(str, 24, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return str;
}

int main(int argc, char **argv) {
    char *dev = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint16_t ethType;

    if (argc != 2) {
        fprintf(stderr, "usage: ./juno_pcap <device_name>\n");
        return 2;
    } else {
        dev = argv[1];
    }

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    printf("Device: %s\n", dev);
    p = pcap_open_live(dev, 16384, 1, 200, errbuf);

    if (p == NULL) {
        fprintf(stderr, "Couldn't open pcap: %s\n", errbuf);
        return 2;
    }

    const struct pcap_pkthdr *ph;
    const u_char *pd;
    const struct libnet_ethernet_hdr *ethHeader;

    while (pcap_next_ex(p, &ph, &pd)) {

        ethHeader = (const struct libnet_ethernet_hdr *)pd;

        puts("\x1B[32m============== Packet ==============\x1B[0m");

        printf("\x1B[34mcapture len: %d\n", ph->caplen);

        printf("\x1B[31msrc  mac -> %s\n", hex2mac(ethHeader->ether_shost));
        printf("\x1B[36mdest mac -> %s\n", hex2mac(ethHeader->ether_dhost));

        ethType = ntohs(ethHeader->ether_type);

        if (ethType != ETHERTYPE_IP) {
            continue;
        }

        const char *ethDesc;
        ethDesc = get_eth_type_descr(ethType);

        printf("\x1B[93mether type -> %#x, %s\n", ethType, ethDesc);

        const struct libnet_ipv4_hdr *ipHeader = (const struct libnet_ipv4_hdr *)(pd + 14);
        const uint32_t ipHeaderLen = ipHeader->ip_hl * 4;
        const uint8_t *ipData;

        char ip_buffer[16];
        memset(ip_buffer, 16, 0);
        inet_ntop(AF_INET, &ipHeader->ip_src.s_addr, ip_buffer, 16);
        printf("\x1B[31msrc ip  -> %s\n", ip_buffer);

        memset(ip_buffer, 16, 0);
        inet_ntop(AF_INET, &ipHeader->ip_dst.s_addr, ip_buffer, 16);
        printf("\x1B[36mdest ip -> %s\n", ip_buffer);

        printf("\x1B[35mttl: %u\n", ipHeader->ip_ttl);
        printf("\x1B[95mprotocol: %u\n", ipHeader->ip_p);

        if (ipHeader->ip_p != IP_TCP) {
            continue;
        }

        ipData = ((uint8_t *)ipHeader) + ipHeaderLen;
        const struct libnet_tcp_hdr *tcpHeader = ((const struct libnet_tcp_hdr *)ipData);
        printf("\x1B[31msport: %u\n", ntohs(tcpHeader->th_sport));
        printf("\x1B[36mdport: %u\n", ntohs(tcpHeader->th_dport));
        printf("\x1B[92mtcp_seq -> %u\n", ntohl(tcpHeader->th_seq));
        printf("\x1B[92mtcp_ack -> %u\n", ntohl(tcpHeader->th_ack));

        const char *tcpPayload = ipData + sizeof(*tcpHeader);

        const uint16_t tcpPayloadLen = ph->caplen - ((const char *)tcpPayload - (const char *)pd);
        
        DumpHex(tcpPayload, tcpPayloadLen);

    }

    pcap_close(p);
    p = NULL;

    return 0;
}

