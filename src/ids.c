#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>   /* ntohs, ntohl, inet_ntop */
#include <ctype.h>       /* isprint */
#include <unistd.h>      /* getopt */

#include "net_structs.h"
#include "sigmatch.h"


/*
 * nids -- a minimal offline Network Intrusion Detection System.
 *
 * Phase 1: zero-copy protocol parsing. We read packets from a saved .pcap
 * file and walk the header stack (Ethernet -> IPv4 -> TCP) by casting struct
 * pointers over the raw byte buffer, never copying. The goal of this phase is
 * to locate the application payload so later phases can scan it for malware
 * signatures.
 *
 * Phase 2: signature matching. Each payload is scanned against a rules file
 * (see sigmatch.c) and every hit is printed as an ALERT line.
 *
 * Usage:  ./ids [-v] <capture.pcap> [rules]     (-v also prints every TCP packet)
 */

struct capture_stats {
    unsigned long total;   /* every packet pcap handed us          */
    unsigned long ipv4;    /* packets that were IPv4               */
    unsigned long tcp;     /* IPv4 packets whose L4 protocol is TCP */
    unsigned long alerts;
};

struct ids_ctx {
    struct capture_stats   stats;
    struct sig_matcher    *sigs;
    int                    verbose;
    const struct ipv4_hdr *ip;     /* packet being scanned, for alert lines */
    const struct tcp_hdr  *tcp;
};

static void on_alert(const struct sig_rule *rule, size_t offset, void *user)
{
    struct ids_ctx *ctx = (struct ids_ctx *)user;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ctx->ip->src_addr, src, sizeof src);
    inet_ntop(AF_INET, &ctx->ip->dst_addr, dst, sizeof dst);
    printf("ALERT pkt=%lu sid=%u msg=\"%s\" %s:%u -> %s:%u offset=%zu\n",
           ctx->stats.total, rule->sid, rule->msg,
           src, ntohs(ctx->tcp->src_port), dst, ntohs(ctx->tcp->dst_port), offset);
    ctx->stats.alerts++;
}

static void handle_packet(u_char *user,
                          const struct pcap_pkthdr *header,
                          const u_char *packet)
{
    struct ids_ctx *ctx = (struct ids_ctx *)user;
    struct capture_stats *stats = &ctx->stats;
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

    if (IPV4_VERSION(ip) != 4 || IPV4_HDR_LEN(ip) < sizeof(struct ipv4_hdr))
        return;

    stats->ipv4++;

    uint32_t ip_hdr_len = IPV4_HDR_LEN(ip);       

    if (ip->protocol != IPPROTO_TCP)
        return;                                  
    if (ntohs(ip->flags_frag) & 0x1FFF)
        return;                                   /* non-first fragment */
    stats->tcp++;



    if (ctx->verbose) {
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->src_addr, src, sizeof src);
        inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof dst);
        printf("[%lu] TCP  %s -> %s  (ip_hdr_len=%u, caplen=%u)\n",
               stats->total, src, dst, ip_hdr_len, header->caplen);
    }


    if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + sizeof(struct tcp_hdr))
        return;
    const struct tcp_hdr *tcp =
        (const struct tcp_hdr *)((const uint8_t *)ip + ip_hdr_len);

    uint32_t tcp_hdr_len = TCP_HDR_LEN(tcp);
    if (tcp_hdr_len < sizeof(struct tcp_hdr))
        return;
    if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len)
        return;

    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;

    int payload_len = (int)ntohs(ip->total_len) - (int)ip_hdr_len - (int)tcp_hdr_len;
    if (payload_len < 0)
        return;

    uint32_t available = header->caplen - (ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len);
    if ((uint32_t)payload_len > available)
        payload_len = (int)available;

    if (ctx->verbose) {
        printf("      payload: %d bytes  \"", payload_len);
        for (int i = 0; i < payload_len && i < 40; i++)
            putchar(isprint(payload[i]) ? payload[i] : '.');
        printf("\"\n");
    }

    ctx->ip = ip;
    ctx->tcp = tcp;
    sig_scan(ctx->sigs, payload, (size_t)payload_len, on_alert, ctx);
}

int main(int argc, char **argv)
{
    struct ids_ctx ctx = {0};
    int opt, bad = 0;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        if (opt == 'v')
            ctx.verbose = 1;
        else
            bad = 1;
    }
    if (bad || argc - optind < 1 || argc - optind > 2) {
        fprintf(stderr, "usage: %s [-v] <capture.pcap> [rules]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *pcap_path  = argv[optind];
    const char *rules_path = argc - optind == 2 ? argv[optind + 1] : "rules/default.rules";

    ctx.sigs = sig_load(rules_path);
    if (ctx.sigs == NULL)
        return EXIT_FAILURE;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "error: could not open '%s': %s\n", pcap_path, errbuf);
        sig_free(ctx.sigs);
        return EXIT_FAILURE;
    }

    /* Our struct offsets assume Ethernet (DLT_EN10MB). Bail loudly on anything
       else (e.g. Linux "cooked" captures or raw IP) so we don't misparse. */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "error: unsupported link type %d (expected Ethernet)\n",
                pcap_datalink(handle));
        pcap_close(handle);
        sig_free(ctx.sigs);
        return EXIT_FAILURE;
    }

    /* 0 = loop until the file is exhausted. */
    if (pcap_loop(handle, 0, handle_packet, (u_char *)&ctx) == PCAP_ERROR) {
        fprintf(stderr, "error during capture: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        sig_free(ctx.sigs);
        return EXIT_FAILURE;
    }

    pcap_close(handle);
    sig_free(ctx.sigs);

    printf("\n---\n%lu packets, %lu IPv4, %lu TCP, %lu alerts\n",
           ctx.stats.total, ctx.stats.ipv4, ctx.stats.tcp, ctx.stats.alerts);
    return EXIT_SUCCESS;
}
