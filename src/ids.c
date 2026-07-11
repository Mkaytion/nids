#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>   /* ntohs, ntohl, inet_ntop */
#include <ctype.h>       /* isprint */

#include "net_structs.h"


/*
 * nids -- a minimal offline Network Intrusion Detection System.
 *
 * Phase 1: zero-copy protocol parsing. We read packets from a saved .pcap
 * file and walk the header stack (Ethernet -> IPv4 -> TCP) by casting struct
 * pointers over the raw byte buffer, never copying. The goal of this phase is
 * to locate the application payload so later phases can scan it for malware
 * signatures.
 *
 * Usage:  ./ids <capture.pcap>
 */

struct capture_stats {
    unsigned long total;   /* every packet pcap handed us          */
    unsigned long ipv4;    /* packets that were IPv4               */
    unsigned long tcp;     /* IPv4 packets whose L4 protocol is TCP */
};

static void handle_packet(u_char *user,
                          const struct pcap_pkthdr *header,
                          const u_char *packet)
{
    struct capture_stats *stats = (struct capture_stats *)user;
    stats->total++;

    /* --- Layer 2: Ethernet ------------------------------------------------ */
    if (header->caplen < ETHER_HDR_LEN)
        return;                                   /* too short to be Ethernet */

    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    if (ntohs(eth->ethertype) != ETHERTYPE_IP)
        return;                                   /* not IPv4 -> skip for now */

    /* --- Layer 3: IPv4 ------------------------------------------------- */
    /* The IP header sits immediately after the fixed 14-byte Ethernet header. */
    const struct ipv4_hdr *ip =
        (const struct ipv4_hdr *)(packet + ETHER_HDR_LEN);

    /* Make sure the fixed part of the IP header is within the captured bytes
       before dereferencing ver_ihl / protocol. */
    if (header->caplen < ETHER_HDR_LEN + sizeof(struct ipv4_hdr))
        return;

    stats->ipv4++;

    uint32_t ip_hdr_len = IPV4_HDR_LEN(ip);       

    if (ip->protocol != IPPROTO_TCP)
        return;                                  
    stats->tcp++;



    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->src_addr, src, sizeof src);
    inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof dst);
    printf("[%lu] TCP  %s -> %s  (ip_hdr_len=%u, caplen=%u)\n",
           stats->total, src, dst, ip_hdr_len, header->caplen);


    if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + sizeof(struct tcp_hdr))
        return;
    const struct tcp_hdr *tcp =
        (const struct tcp_hdr *)((const uint8_t *)ip + ip_hdr_len);

    uint32_t tcp_hdr_len = TCP_HDR_LEN(tcp);
    if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len)
        return;

    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;

    int payload_len = (int)ntohs(ip->total_len) - (int)ip_hdr_len - (int)tcp_hdr_len;
    if (payload_len < 0)
        return;

    uint32_t available = header->caplen - (ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len);
    if ((uint32_t)payload_len > available)
        payload_len = (int)available;

    printf("      payload: %d bytes  \"", payload_len);
    for (int i = 0; i < payload_len && i < 40; i++)
        putchar(isprint(payload[i]) ? payload[i] : '.');
    printf("\"\n");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <capture.pcap>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "error: could not open '%s': %s\n", argv[1], errbuf);
        return EXIT_FAILURE;
    }

    /* Our struct offsets assume Ethernet (DLT_EN10MB). Bail loudly on anything
       else (e.g. Linux "cooked" captures or raw IP) so we don't misparse. */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "error: unsupported link type %d (expected Ethernet)\n",
                pcap_datalink(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    struct capture_stats stats = {0, 0, 0};

    /* 0 = loop until the file is exhausted. */
    if (pcap_loop(handle, 0, handle_packet, (u_char *)&stats) == PCAP_ERROR) {
        fprintf(stderr, "error during capture: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);

    printf("\n---\n%lu packets, %lu IPv4, %lu TCP\n",
           stats.total, stats.ipv4, stats.tcp);
    return EXIT_SUCCESS;
}
