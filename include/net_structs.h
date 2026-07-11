#ifndef NET_STRUCTS_H
#define NET_STRUCTS_H

#include <stdint.h>


/* ------------------------------------------------------------------ */
/* Layer 2: Ethernet II                                               */
/* ------------------------------------------------------------------ */

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN  14      /* 6 + 6 + 2, fixed size                */
#define ETHERTYPE_IP   0x0800  /* value (host order) after ntohs()     */

struct eth_hdr {
    uint8_t  dst_mac[ETHER_ADDR_LEN];
    uint8_t  src_mac[ETHER_ADDR_LEN];
    uint16_t ethertype;        /* network byte order: compare via ntohs() */
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* Layer 3: IPv4                                                      */
/* ------------------------------------------------------------------ */

#ifndef IPPROTO_TCP            /* system <netinet/in.h> may already define it */
#define IPPROTO_TCP 6          /* value stored in ipv4_hdr.protocol    */
#endif

struct ipv4_hdr {
    uint8_t  ver_ihl;          /* high nibble: version; low nibble: IHL */
    uint8_t  tos;
    uint16_t total_len;        /* network byte order                    */
    uint16_t id;
    uint16_t flags_frag;       /* 3-bit flags + 13-bit fragment offset  */
    uint8_t  ttl;
    uint8_t  protocol;         /* e.g. IPPROTO_TCP                      */
    uint16_t checksum;
    uint32_t src_addr;         /* network byte order                    */
    uint32_t dst_addr;         /* network byte order                    */
    /* Options may follow if IHL > 5 — that's exactly why the header
       length is variable and must be computed, not assumed. */
} __attribute__((packed));

/* The IHL field counts 32-bit words, so the real header length in BYTES
   is IHL * 4. For a header with no options IHL == 5 -> 20 bytes. */
#define IPV4_VERSION(ip) (((ip)->ver_ihl >> 4) & 0x0F)
#define IPV4_IHL(ip)     ((ip)->ver_ihl & 0x0F)
#define IPV4_HDR_LEN(ip) (IPV4_IHL(ip) * 4)



struct tcp_hdr {
    uint16_t src_port;         /* network byte order                    */
    uint16_t dst_port;         /* network byte order                    */
    uint32_t seq;              /* sequence number                       */
    uint32_t ack;              /* acknowledgment number                  */
    uint8_t  data_off_rsvd;    /* high nibble: data offset, low nibble: reserved */
    uint8_t  flags;            /* control flags (SYN, ACK, FIN, etc.)   */
    uint16_t window;           /* window size                            */
    uint16_t checksum;         /* checksum                               */
    uint16_t urg_ptr;          /* urgent pointer                         */
} __attribute__((packed));

#define TCP_DATA_OFFSET(tcp) (((tcp)->data_off_rsvd >> 4) & 0x0F)
#define TCP_HDR_LEN(tcp)     (TCP_DATA_OFFSET(tcp) * 4)

#endif /* NET_STRUCTS_H */  
