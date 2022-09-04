/*

    TODO: NO CLIENTE, VAI TER QUE ALTERAR A PORTA DE TEMPOS EM TEMPOS SE NAO ESTIVER FUNCIONANDO
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/addrconf.h>
#include <linux/module.h>

#if XGW_XTUN_ASSERT
#define XTUN_ASSERT(c) ({ if (!(c)) printk("ASSERT FAILED: " #c "\n"); })
#else
#define XTUN_ASSERT(c) ({})
#endif

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef unsigned long long int uintll;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

#define foreach(i, t) for (uint i = 0; i != (t); i++)

static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define __A6(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
#define __A4(x) (x)[0], (x)[1], (x)[2], (x)[3]

#define _MAC(x) __A6(x)
#define _IP4(x) __A4(x)

#define MAC__(a,b,c) a ## b ## c
#define MAC_(x) MAC__(0x,x,U)
#define MAC(a,b,c,d,e,f) { MAC_(a), MAC_(b), MAC_(c), MAC_(d), MAC_(e), MAC_(f) }

#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))

#define XTUN_PATHS_N XGW_XTUN_PATHS_N

#define XTUN_SERVER      XGW_XTUN_SERVER_IS
#define XTUN_SERVER_PORT XGW_XTUN_SERVER_PORT

#if XTUN_SERVER
#define XTUN_NODES_N XGW_XTUN_NODES_N
#else
#define XTUN_NODE_ID XGW_XTUN_NODE_ID
#endif

#if ! (1 <= XTUN_PATHS_N && XTUN_PATHS_N <= 4)
#error "BAD XTUN_PATHS_N"
#endif

#if ! (1 <= XTUN_SERVER_PORT && XTUN_SERVER_PORT <= 0xFFFF)
#error "BAD XTUN_SERVER_PORT"
#endif

#if XTUN_SERVER
#if ! (1 <= XTUN_NODES_N && XTUN_NODES_N <= 0xFFFF)
#error "BAD XTUN_NODES_N"
#endif
#elif ! (0 <= XTUN_NODE_ID && XTUN_NODE_ID <= 0xFFFF)
#error "BAD XTUN_NODE_ID"
#endif

#include "xtun-crypto.c"

//
#define PORT(nid, pid) (XTUN_SERVER_PORT + (nid)*10 + (pid))
// WILL UNSIGNED OVERFLOW IF LOWER
#define PORT_NID(port) (((port) - XTUN_SERVER_PORT) / 10)
#define PORT_PID(port) (((port) - XTUN_SERVER_PORT) % 10)

//
#if XTUN_SERVER && PORT(XTUN_NODES_N - 1, XTUN_PATHS_N - 1) > 0xFFFF
#error "BAD XTUN_SERVER_PORT / XTUN_NODES_N / XTUN_PATHS_N"
#endif

//
#if 0
#define XTUN_DEV_PRIV_SIZE sizeof(xtun_node_s*)
#define XTUN_DEV_NODE(dev) (*(xtun_node_s**)netdev_priv(dev))
#else
#define XTUN_DEV_PRIV_SIZE 0
#define XTUN_DEV_NODE(dev) ((dev)->rx_handler_data)
#endif

// EXPECTED SIZE
#define XTUN_PATH_SIZE CACHE_LINE_SIZE
#define XTUN_PATH_SIZE_PRIVATE (XTUN_PATH_SIZE - XTUN_PATH_SIZE_WIRE)
#define XTUN_PATH_SIZE_WIRE (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE)

#define PATH_ETH(path) PTR(&(path)->eDst)
#define PATH_IP(path)  PTR(&(path)->iVersion)
#define PATH_UDP(path) PTR(&(path)->uSrc)

#define XTUN_PATH_F_UP                 0b0000000000000001U // ADMINISTRATIVELY
#define XTUN_PATH_F_UP_AUTO            0b0000000000000010U // SE DER TIMEOUT VAI DESATIVAR ISSO
#define XTUN_PATH_F_UP_ITFC            0b0000000000000100U // WATCH INTERFACE EVENTS AND SET THIS TODO: INICIALIZAR COMO 0 E CARREGAR ISSO NO DEVICE NOTIFIER
#if XTUN_SERVER
#define XTUN_PATH_F_ITFC_LEARN         0b0000000000001000U
#define XTUN_PATH_F_E_SRC_LEARN        0b0000000000010000U
#define XTUN_PATH_F_E_DST_LEARN        0b0000000000100000U
#define XTUN_PATH_F_I_SRC_LEARN        0b0000000001000000U
#define XTUN_PATH_F_I_DST_LEARN        0b0000000010000000U    // TODO: TIME DO ULTIMO RECEBIDO; DESATIVAR O PATH NO SERVIDOR SE NAO RECEBER NADA EM TANTO TEMPO
#define XTUN_PATH_F_U_DST_LEARN        0b0000000100000000U
#endif

#define FLAGS_IS_UP(f) (((f) & (XTUN_PATH_F_UP | XTUN_PATH_F_UP_AUTO | XTUN_PATH_F_UP_ITFC)) \
                            == (XTUN_PATH_F_UP | XTUN_PATH_F_UP_AUTO | XTUN_PATH_F_UP_ITFC))

typedef struct xtun_path_s {
    net_device_s* itfc;
#if XTUN_SERVER
    u64 hash; // THE PATH HASH
#else
    u64 reserved2;
#endif
    u16 reserved;
    u16 flags;
    u16 band;
#define ETH_HDR_SIZE 14
    u8  eDst[ETH_ALEN];
    u8  eSrc[ETH_ALEN];
    u16 eType;
#define IP4_HDR_SIZE 20
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iHash; // A CHECKSUM TO CONFIRM THE AUTHENTICITY OF THE PACKET
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iCksum;
    u8  iSrc[4];
    u8  iDst[4];
#define UDP_HDR_SIZE 8
    u16 uSrc;
    u16 uDst; // THE XTUN_SERVER PORT WILL DETERMINE THE NODE AND PATH
    u16 uSize;
    u16 uCksum;
} xtun_path_s;

#define XTUN_FLOWS_N 64

// EXPECTED SIZE
#define XTUN_NODE_SIZE ((2 + XTUN_PATHS_N)*CACHE_LINE_SIZE)

typedef struct xtun_node_s {
    net_device_s* dev;
    xtun_crypto_params_s cryptoParams;
    u64 reserved2;
    u16 cryptoAlgo;
    u16 reserved;
    u16 mtu; // TODO: FIXME:
    u16 flowShift; // SHIFTA TODOS OS FLOW IDS AO MESMO TEMPO, AO SELECIONAR O PATH
    u32 flowRemaining; // QUANTOS PACOTES ENVIAR ATÉ AVANÇAR O FLOW SHIFT
    u32 flowPackets; // O QUE USAR COMO FLOW REMAINING
    u8  flows[XTUN_FLOWS_N]; // MAPA FLOW ID -> PATH ID
    xtun_path_s paths[XTUN_PATHS_N];
} xtun_node_s;

typedef struct xtun_cfg_path_s {
    char itfc[IFNAMSIZ];
    u8 mac[ETH_ALEN];
    u8 gw[ETH_ALEN];
    u8 addr[4];
    u16 port;
    u8 tos;
    u8 ttl;
    uint band; // TOTAL DE PACOTES A CADA CIRCULADA
} xtun_cfg_path_s;

typedef struct xtun_cfg_node_srv_s {
    uint mtu;
    uint pkts;
    xtun_crypto_params_s cryptoParams;
    xtun_crypto_algo_e cryptoAlgo;
    xtun_cfg_path_s paths[XTUN_PATHS_N];
} xtun_cfg_node_side_s;

typedef struct xtun_cfg_node_s {
    uint id;
    char name[IFNAMSIZ];
    xtun_cfg_node_side_s clt;
    xtun_cfg_node_side_s srv;
} xtun_cfg_node_s;

#if XTUN_SERVER
#define NODE_ID(node) ((uint)((node) - nodes))
static xtun_node_s nodes[XTUN_NODES_N];
#else
#define NODE_ID(node) XTUN_NODE_ID
static xtun_node_s node[1];
#endif

#if XTUN_SERVER
#define CONF_ID(nid) .id = (nid), .name = "xgw-" # nid
#else
#define CONF_ID(nid) .id = (nid), .name = "xgw"
#endif

static const xtun_cfg_node_s cfgNodes[] = {
#if (XTUN_SERVER && XTUN_NODES_N > 1) || XTUN_NODE_ID == 1
    { CONF_ID(1),
        .clt = { .mtu = XGW_XTUN_NODE_1_CLT_MTU, .pkts = XGW_XTUN_NODE_1_CLT_PKTS, .cryptoAlgo = XTUN_CRYPTO_ALGO_NULL0, .paths = {
            { .itfc = XGW_XTUN_NODE_1_CLT_PATH_0_ITFC, .band = XGW_XTUN_NODE_1_CLT_PATH_0_BAND, .mac = XGW_XTUN_NODE_1_CLT_PATH_0_MAC, .gw = XGW_XTUN_NODE_1_CLT_PATH_0_GW, .addr = {XGW_XTUN_NODE_1_CLT_PATH_0_ADDR_0,XGW_XTUN_NODE_1_CLT_PATH_0_ADDR_1,XGW_XTUN_NODE_1_CLT_PATH_0_ADDR_2,XGW_XTUN_NODE_1_CLT_PATH_0_ADDR_3}, .tos = XGW_XTUN_NODE_1_CLT_PATH_0_TOS, .ttl = XGW_XTUN_NODE_1_CLT_PATH_0_TTL, .port = XGW_XTUN_NODE_1_CLT_PATH_0_PORT, },
#if XTUN_PATHS_N > 1
            { .itfc = XGW_XTUN_NODE_1_CLT_PATH_1_ITFC, .band = XGW_XTUN_NODE_1_CLT_PATH_1_BAND, .mac = XGW_XTUN_NODE_1_CLT_PATH_1_MAC, .gw = XGW_XTUN_NODE_1_CLT_PATH_1_GW, .addr = {XGW_XTUN_NODE_1_CLT_PATH_1_ADDR_0,XGW_XTUN_NODE_1_CLT_PATH_1_ADDR_1,XGW_XTUN_NODE_1_CLT_PATH_1_ADDR_2,XGW_XTUN_NODE_1_CLT_PATH_1_ADDR_3}, .tos = XGW_XTUN_NODE_1_CLT_PATH_1_TOS, .ttl = XGW_XTUN_NODE_1_CLT_PATH_1_TTL, .port = XGW_XTUN_NODE_1_CLT_PATH_1_PORT, },
#if XTUN_PATHS_N > 2
            { .itfc = XGW_XTUN_NODE_1_CLT_PATH_2_ITFC, .band = XGW_XTUN_NODE_1_CLT_PATH_2_BAND, .mac = XGW_XTUN_NODE_1_CLT_PATH_2_MAC, .gw = XGW_XTUN_NODE_1_CLT_PATH_2_GW, .addr = {XGW_XTUN_NODE_1_CLT_PATH_2_ADDR_0,XGW_XTUN_NODE_1_CLT_PATH_2_ADDR_1,XGW_XTUN_NODE_1_CLT_PATH_2_ADDR_2,XGW_XTUN_NODE_1_CLT_PATH_2_ADDR_3}, .tos = XGW_XTUN_NODE_1_CLT_PATH_2_TOS, .ttl = XGW_XTUN_NODE_1_CLT_PATH_2_TTL, .port = XGW_XTUN_NODE_1_CLT_PATH_2_PORT, },
#if XTUN_PATHS_N > 3
            { .itfc = XGW_XTUN_NODE_1_CLT_PATH_3_ITFC, .band = XGW_XTUN_NODE_1_CLT_PATH_3_BAND, .mac = XGW_XTUN_NODE_1_CLT_PATH_3_MAC, .gw = XGW_XTUN_NODE_1_CLT_PATH_3_GW, .addr = {XGW_XTUN_NODE_1_CLT_PATH_3_ADDR_0,XGW_XTUN_NODE_1_CLT_PATH_3_ADDR_1,XGW_XTUN_NODE_1_CLT_PATH_3_ADDR_2,XGW_XTUN_NODE_1_CLT_PATH_3_ADDR_3}, .tos = XGW_XTUN_NODE_1_CLT_PATH_3_TOS, .ttl = XGW_XTUN_NODE_1_CLT_PATH_3_TTL, .port = XGW_XTUN_NODE_1_CLT_PATH_3_PORT, },
#endif
#endif
#endif
        }},
        .srv = { .mtu = XGW_XTUN_NODE_1_SRV_MTU, .pkts = XGW_XTUN_NODE_1_SRV_PKTS, .cryptoAlgo = XTUN_CRYPTO_ALGO_NULL0, .paths = {
            { .itfc = XGW_XTUN_NODE_1_SRV_PATH_0_ITFC, .band = XGW_XTUN_NODE_1_SRV_PATH_0_BAND, .mac = XGW_XTUN_NODE_1_SRV_PATH_0_MAC, .gw = XGW_XTUN_NODE_1_SRV_PATH_0_GW, .addr = {XGW_XTUN_NODE_1_SRV_PATH_0_ADDR_0,XGW_XTUN_NODE_1_SRV_PATH_0_ADDR_1,XGW_XTUN_NODE_1_SRV_PATH_0_ADDR_2,XGW_XTUN_NODE_1_SRV_PATH_0_ADDR_3}, .tos = XGW_XTUN_NODE_1_SRV_PATH_0_TOS, .ttl = XGW_XTUN_NODE_1_SRV_PATH_0_TTL, .port = PORT(0, 0), },
#if XTUN_PATHS_N > 1
            { .itfc = XGW_XTUN_NODE_1_SRV_PATH_1_ITFC, .band = XGW_XTUN_NODE_1_SRV_PATH_1_BAND, .mac = XGW_XTUN_NODE_1_SRV_PATH_1_MAC, .gw = XGW_XTUN_NODE_1_SRV_PATH_1_GW, .addr = {XGW_XTUN_NODE_1_SRV_PATH_1_ADDR_0,XGW_XTUN_NODE_1_SRV_PATH_1_ADDR_1,XGW_XTUN_NODE_1_SRV_PATH_1_ADDR_2,XGW_XTUN_NODE_1_SRV_PATH_1_ADDR_3}, .tos = XGW_XTUN_NODE_1_SRV_PATH_1_TOS, .ttl = XGW_XTUN_NODE_1_SRV_PATH_1_TTL, .port = PORT(0, 1), },
#if XTUN_PATHS_N > 2
            { .itfc = XGW_XTUN_NODE_1_SRV_PATH_2_ITFC, .band = XGW_XTUN_NODE_1_SRV_PATH_2_BAND, .mac = XGW_XTUN_NODE_1_SRV_PATH_2_MAC, .gw = XGW_XTUN_NODE_1_SRV_PATH_2_GW, .addr = {XGW_XTUN_NODE_1_SRV_PATH_2_ADDR_0,XGW_XTUN_NODE_1_SRV_PATH_2_ADDR_1,XGW_XTUN_NODE_1_SRV_PATH_2_ADDR_2,XGW_XTUN_NODE_1_SRV_PATH_2_ADDR_3}, .tos = XGW_XTUN_NODE_1_SRV_PATH_2_TOS, .ttl = XGW_XTUN_NODE_1_SRV_PATH_2_TTL, .port = PORT(0, 2), },
#if XTUN_PATHS_N > 3
            { .itfc = XGW_XTUN_NODE_1_SRV_PATH_3_ITFC, .band = XGW_XTUN_NODE_1_SRV_PATH_3_BAND, .mac = XGW_XTUN_NODE_1_SRV_PATH_3_MAC, .gw = XGW_XTUN_NODE_1_SRV_PATH_3_GW, .addr = {XGW_XTUN_NODE_1_SRV_PATH_3_ADDR_0,XGW_XTUN_NODE_1_SRV_PATH_3_ADDR_1,XGW_XTUN_NODE_1_SRV_PATH_3_ADDR_2,XGW_XTUN_NODE_1_SRV_PATH_3_ADDR_3}, .tos = XGW_XTUN_NODE_1_SRV_PATH_3_TOS, .ttl = XGW_XTUN_NODE_1_SRV_PATH_3_TTL, .port = PORT(0, 3), },
#endif
#endif
#endif
        }}
    },
#endif
};

static void xtun_node_flows_update (xtun_node_s* const node) {

    uint total = 0;
    uint maiorB = 0;
    uint maiorP = 0;

    foreach (pid, XTUN_PATHS_N) {
        const uint b = FLAGS_IS_UP(node->paths[pid].flags) * node->paths[pid].band;
        // CALCULA O TOTAL
        total += b;
        // LEMBRA O PATH COM MAIOR BANDWIDTH
        // LEMBRA O BANDWIDTH DELE
        if (maiorB < b) {
            maiorB = b;
            maiorP = pid;
        }
    }

    u8* flow = node->flows;
    uint pid = maiorP;

    if (total) {
        do {
            for (uint q = ( (uintll)XTUN_FLOWS_N * FLAGS_IS_UP(node->paths[pid].flags) * node->paths[pid].band
                ) / total; q; q--)
                *flow++ = pid;
            pid = (pid + 1) % XTUN_PATHS_N;
        } while (flow != &node->flows[XTUN_FLOWS_N] && pid != maiorP);
    }

    // O QUE SOBRAR DEIXA COM O MAIOR PATH
    while (flow != &node->flows[XTUN_FLOWS_N])
          *flow++ = pid;

    // PRINT IT
    char flowsStr[XTUN_FLOWS_N + 1];

    foreach (fid, XTUN_FLOWS_N)
        flowsStr[fid] = '0' + node->flows[fid];
    flowsStr[XTUN_FLOWS_N] = '\0';

    printk("XTUN: NODE %u: FLOWS UPDATED: PACKETS %u REMAINING %u FLOWS %s\n",
        NODE_ID(node), node->flowPackets, node->flowRemaining, flowsStr);
}

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb))
        goto drop;

    const xtun_path_s* const hdr = PTR(skb->data) + IP4_HDR_SIZE + UDP_HDR_SIZE - sizeof(xtun_path_s);

    XTUN_ASSERT(PTR(skb_network_header(skb)) == skb->data);
    XTUN_ASSERT((PTR(skb_network_header(skb)) + skb->len) == SKB_TAIL(skb));
    XTUN_ASSERT(PTR(PATH_ETH(hdr)) >= PTR(skb->head));
    XTUN_ASSERT((PTR(PATH_ETH(hdr)) + XTUN_PATH_SIZE_WIRE) <= SKB_TAIL(skb));

    // IDENTIFY NODE AND PATH IDS FROM SERVER PORT
#if XTUN_SERVER
    const uint port = BE16(hdr->uDst);
#else
    const uint port = BE16(hdr->uSrc);
#endif
    const uint nid = PORT_NID(port);
    const uint pid = PORT_PID(port);

    // CONFIRM PACKET SIZE
    // CONFIRM THIS IS ETHERNET/IPV4/UDP
    // VALIDATE NODE ID
    // VALIDATE PATH ID
    if (skb->len <= XTUN_PATH_SIZE_WIRE
     || hdr->eType     != BE16(ETH_P_IP)
     || hdr->iVersion  != 0x45
     || hdr->iProtocol != IPPROTO_UDP
#if XTUN_SERVER
     || nid >= XTUN_NODES_N
#else
     || nid != XTUN_NODE_ID
#endif
     || pid >= XTUN_PATHS_N
    )
        return RX_HANDLER_PASS;

#if XTUN_SERVER
    xtun_node_s* const node = &nodes[nid];
#endif

    // CONFIRM WE HAVE THIS TUNNEL
    if (!node->dev)
        goto drop;

    // THE PAYLOAD IS JUST AFTER OUR ENCAPSULATION
    void* const payload = PTR(hdr) + sizeof(xtun_path_s);
    // THE PAYLOAD SIZE IS EVERYTHING EXCEPT OUR ENCAPSULATION
    const uint payloadSize = BE16(hdr->iSize) - IP4_HDR_SIZE - UDP_HDR_SIZE;

    // DROP EMPTY/INCOMPLETE PAYLOADS
    if ((payloadSize == 0) || (payload + payloadSize) > SKB_TAIL(skb))
        goto drop;

    // DECRYPT AND CONFIRM AUTHENTICITY
    if (xtun_crypto_decode(node->cryptoAlgo, &node->cryptoParams, payload, payloadSize) != hdr->iHash)
        goto drop;

    xtun_path_s* const path = &node->paths[pid];

    // DETECT AND UPDATE PATH AVAILABILITY
    if (unlikely(!(path->flags & XTUN_PATH_F_UP_AUTO))) {
        path->flags |= XTUN_PATH_F_UP_AUTO; // TODO: FIXME: IMPLEMENTAR E USAR ISSO
        xtun_node_flows_update(node);
    }
#if XTUN_SERVER
    // DETECT AND UPDATE PATH CHANGES
    net_device_s* const itfc = skb->dev;

    // NOTE: O SERVER NÃO PODE RECEBER ALEATORIAMENTE COM  UM MESMO IP EM MAIS DE UMA INTERACE, SENÃO VAI FICAR TROCANDO TODA HORA AQUI
    const u64 hash = (u64)(uintptr_t)itfc
      + (*(u64*)hdr->eDst) // VAI PEGAR UM PEDAÇO DO eSrc
      + (*(u64*)hdr->eSrc) // VAI PEGAR O eType
      + (*(u64*)hdr->iSrc) // VAI PEGAR O iDst
      + (       hdr->uSrc)
    ;

    if (unlikely(path->hash != hash)) {
        path->hash = hash;

        if (path->flags & XTUN_PATH_F_ITFC_LEARN) // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
            path->itfc = itfc;
        if (path->flags & XTUN_PATH_F_E_SRC_LEARN)
            memcpy(path->eSrc, hdr->eDst, ETH_ALEN);
        if (path->flags & XTUN_PATH_F_E_DST_LEARN)
            memcpy(path->eDst, hdr->eSrc, ETH_ALEN);
        if (path->flags & XTUN_PATH_F_I_SRC_LEARN)
            memcpy(path->iSrc, hdr->iDst, 4);
        if (path->flags & XTUN_PATH_F_I_DST_LEARN)
            memcpy(path->iDst, hdr->iSrc, 4);
        if (path->flags & XTUN_PATH_F_U_DST_LEARN)
            path->uDst = hdr->uSrc;

        printk("XTUN: NODE %u: PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s TOS 0x%02X TTL %u\n"
            " SRC %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n"
            " DST %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
            nid, pid, (uintll)path->hash, path->itfc->name, path->iTOS, path->iTTL,
            _MAC(path->eSrc), _IP4(path->iSrc), BE16(path->uSrc),
            _MAC(path->eDst), _IP4(path->iDst), BE16(path->uDst));
    }
#endif

    // NOTE: MAKE SURE WE DO THE EQUIVALENT OF TRIM
    // pskb_trim(skb, payloadSize);

    // DESENCAPSULA
    skb->ip_summed        = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
    skb->mac_len          = 0;
    skb->len              = payloadSize;
    skb->data             = PTR(payload);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = PTR(payload) - PTR(skb->head);
    skb->tail             = PTR(payload) - PTR(skb->head) + payloadSize;
#else
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = PTR(payload);
    skb->tail             = PTR(payload) + payloadSize;
#endif
    skb->dev              = node->dev;
    skb->protocol         =
        (*(u8*)payload & 0b0100000U) ?
            BE16(ETH_P_IPV6) :
            BE16(ETH_P_IP);

    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    *pskb = NULL;

    return RX_HANDLER_CONSUMED;
}

// SE ESTAMOS ENVIANDO O PACOTE É PORQUE JÁ SABE QUE OS HEADERS ESTÃO CORRETOS
// WE ONLY ALLOW IPV4/IPV6
// WE ONLY ALLOW IPV4 WITHOUT OPTIONS
// WE ONLY ALLOW TRANSPORTS TCP/UDP/SCTP/DCCP
static uint xtun_flow_hash (const void* const payload) {

    u64 hash;

    if (*(u8*)payload == 0x45) {
        // IPV4
        hash  = *(u8* )(payload + 9); // IP PROTOCOL
        hash += *(u64*)(payload + 12); // IP SOURCE AND IP DESTINATION
        hash += *(u32*)(payload + 20); // TRANSPORT SOURCE AND DESTINATION PORTS
    } else {
        // IPV6
#if 0
        hash  = *(u8* )(payload    ) & 0x000FFFFFFFFFFFFFULL; // FLOW LABEL
#else
        hash  = *(u8* )(payload    ) & 0xFFFFFFFFFFFF0F00ULL; // FLOW LABEL
#endif
        hash += *(u8* )(payload + 6); // IP PROTOCOL
        hash += *(u64*)(payload + 8); // IP SOURCE
        hash += *(u64*)(payload + 16); // IP SOURCE
        hash += *(u64*)(payload + 24); // IP DESTINATION
        hash += *(u64*)(payload + 32); // IP DESTINATION
        hash += *(u32*)(payload + 40); // TRANSPORT SOURCE AND DESTINATION PORTS
    }

    hash += hash >> 32;
    hash += hash >> 16;

    return (uint)hash;
}

static netdev_tx_t xtun_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    // ASSERT: skb->len <= xtun->mtu
    // ASSERT: skb->len <= xtun->dev->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER
    // ASSERT: skb->len <= xtun->path->itfc->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER

    void* const payload = skb->data;
    const uint payloadSize = skb->len;

    xtun_path_s* const hdr = PTR(payload) - sizeof(xtun_path_s);
#if XTUN_SERVER
    xtun_node_s* const node = XTUN_DEV_NODE(dev);
#endif

    XTUN_ASSERT(!skb->data_len);
    // APARENTMENTE, PODE TER SIM, CASO O ESTEJA FORWARDING
    //XTUN_ASSERT(!skb->mac_len);
    XTUN_ASSERT(PTR(payload) == PTR(skb_mac_header(skb)));
    XTUN_ASSERT(PTR(payload) == PTR(skb_network_header(skb)));
    XTUN_ASSERT((PTR(payload) + payloadSize) == SKB_TAIL(skb));
    XTUN_ASSERT(PTR(hdr) >= PTR(skb->head));

    if (PTR(hdr) < PTR(skb->head) || skb->data_len)
        goto drop;

    // TODO: FIXME: payloadSize tem que caber no MTU final

    // ENVIA flowPackets, E AÍ AVANCA flowShift
    if (node->flowRemaining == 0) {
        node->flowRemaining = node->flowPackets;
        node->flowShift++;
    } else
        node->flowRemaining--;

    // CHOOSE PATH AND ENCAPSULATE
    memcpy(hdr, &node->paths[
            (
                (skb->mark >= 30000) &&
                (skb->mark <  40000)
                    ? // PATH BY MARK
                        skb->mark
                    : // PATH BY FLOW
                        node->flows[( node->flowShift + (
                            (skb->mark >= 40000) &&
                            (skb->mark <  50000)
                                ? // FLOW BY MARK
                                skb->mark
                                : // FLOW BY HASH
                                xtun_flow_hash(payload)
                        )) % XTUN_FLOWS_N]
            ) % XTUN_PATHS_N
        ], sizeof(xtun_path_s));

    // ENCRYPT AND AUTHENTIFY
    hdr->iHash = xtun_crypto_encode(node->cryptoAlgo, &node->cryptoParams, payload, payloadSize);
    hdr->uSize  = BE16(payloadSize + UDP_HDR_SIZE);
    hdr->iSize  = BE16(payloadSize + UDP_HDR_SIZE + IP4_HDR_SIZE);
    hdr->iCksum = ip_fast_csum(PATH_IP(hdr), 5);

    skb->len              = payloadSize + XTUN_PATH_SIZE_WIRE;
    skb->data             = PATH_ETH(hdr);
    skb->mac_header       = PATH_ETH(hdr) - PTR(skb->head);
    skb->network_header   = PATH_IP(hdr)  - PTR(skb->head);
    skb->transport_header = PATH_UDP(hdr) - PTR(skb->head);
    skb->protocol         = BE16(ETH_P_IP);
    skb->ip_summed        = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
    skb->mac_len          = ETH_HLEN;

    // TODO: SE XTUN_PATH_F_UP_ITFC FOR TRUE, ENTAO hdr->itfc JÁ É TRUE
    // TODO: FIXME: CONSOLIDAR TODOS ESSES CHECKS EM UMA COISA SO TODA VEZ QUE ALTERAR ALGUM DELES
    if (!(FLAGS_IS_UP(hdr->flags) && hdr->itfc && hdr->itfc->flags & IFF_UP))
        goto drop;

    // TODO: AO TROCAR TEM QUE DAR dev_put(skb->dev) ?
    skb->dev = hdr->itfc;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xtun_dev_up (net_device_s* const dev) {

    return 0;
}

static int xtun_dev_down (net_device_s* const dev) {

    return 0;
}

static int xtun_dev_header_create (sk_buff_s *skb, net_device_s *dev, unsigned short type, const void *daddr, const void *saddr, uint len) {

    return 0;
}

static const header_ops_s xtunHeaderOps = {
    .create = xtun_dev_header_create,
};

static const net_device_ops_s xtunDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xtun_dev_up,
    .ndo_stop             =  xtun_dev_down,
    .ndo_start_xmit       =  xtun_dev_start_xmit,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO PODE SER MAIOR QUE A INTERFACE DE CIMA
};

static void xtun_dev_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xtunDevOps;
    dev->header_ops      = &xtunHeaderOps;
    dev->type            = ARPHRD_NONE;
    dev->hard_header_len = sizeof(xtun_path_s); // ETH_HLEN
    dev->min_header_len  = sizeof(xtun_path_s);
    dev->mtu             = ETH_DATA_LEN - XTUN_PATH_SIZE_WIRE;
    dev->min_mtu         = ETH_MIN_MTU  - XTUN_PATH_SIZE_WIRE;
    dev->max_mtu         = ETH_MAX_MTU  - XTUN_PATH_SIZE_WIRE;
    dev->addr_len        = 0;
    dev->tx_queue_len    = 0; // EFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
                         | IFF_NO_RX_HANDLER
        ;
}

#if XTUN_SERVER
#define this srv
#define thisPath spath
#define peer clt
#define peerPath cpath
#else
#define this clt
#define thisPath cpath
#define peer srv
#define peerPath spath
#endif

static void xtun_path_init (xtun_node_s* const restrict node, const uint nid, xtun_path_s* const restrict path, const uint pid, const xtun_cfg_node_s* const restrict cfg) {

    const xtun_cfg_path_s* const cpath = &cfg->clt.paths[pid];
    const xtun_cfg_path_s* const spath = &cfg->srv.paths[pid];

    printk("XTUN: NODE %u: PATH %u: INITIALIZING\n"
        " THIS BAND %8u ITFC %16s MAC %02X:%02X:%02X:%02X:%02X:%02X GW %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %5u TOS 0x%02X TTL %3u\n"
        " PEER BAND %8u ITFC %16s MAC %02X:%02X:%02X:%02X:%02X:%02X GW %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %5u TOS 0x%02X TTL %3u\n",
        nid, pid,
        thisPath->band, thisPath->itfc, _MAC(thisPath->mac), _MAC(thisPath->gw), _IP4(thisPath->addr), thisPath->port, thisPath->tos, thisPath->ttl,
        peerPath->band, peerPath->itfc, _MAC(peerPath->mac), _MAC(peerPath->gw), _IP4(peerPath->addr), peerPath->port, peerPath->tos, peerPath->ttl
    );

    path->flags =
          (XTUN_PATH_F_UP          * !0)
        | (XTUN_PATH_F_UP_AUTO     * !0)
#if XTUN_SERVER
        | (XTUN_PATH_F_ITFC_LEARN  * !0)
        | (XTUN_PATH_F_E_SRC_LEARN * !0)
        | (XTUN_PATH_F_E_DST_LEARN * !0)
        | (XTUN_PATH_F_I_SRC_LEARN * !0)
        | (XTUN_PATH_F_I_DST_LEARN * !0)
        | (XTUN_PATH_F_U_DST_LEARN * !0)
#endif
        ;
    path->itfc       = NULL;
#if XTUN_SERVER
    path->hash       = 0;

#else
    path->reserved2  = 0;
#endif
    path->reserved   = 0;
    path->band       = thisPath->band;
    path->eType      = BE16(ETH_P_IP);
    path->iVersion   = 0x45;
    path->iTOS       = thisPath->tos;
 // path->iSize
    path->iHash      = 0;
    path->iFrag      = 0;
    path->iTTL       = thisPath->ttl;
    path->iProtocol  = IPPROTO_UDP;
    path->iCksum     = 0;
    path->uSrc       = BE16(thisPath->port);
    path->uDst       = BE16(peerPath->port);
 // path->uSize
    path->uCksum     = 0;

    memcpy(path->eSrc, thisPath->mac, ETH_ALEN);
    memcpy(path->eDst, thisPath->gw,  ETH_ALEN);

    memcpy(path->iSrc, thisPath->addr, 4);
    memcpy(path->iDst, peerPath->addr, 4);

    net_device_s* const itfc = dev_get_by_name(&init_net, thisPath->itfc);

    if (itfc) {

        rtnl_lock();

        // HOOK INTERFACE
        if (rcu_dereference(itfc->rx_handler) != xtun_in) {
            // NOT HOOKED YET
            if (!netdev_rx_handler_register(itfc, xtun_in, NULL)) {
                // HOOK SUCCESS
                // NOTE: ISSO É PARA QUE POSSA DAR FORWARD NOS PACOTES
                // NOTE: A INTERFACE JA TEM O ETH_HLEN
                itfc->hard_header_len += sizeof(xtun_path_s) - ETH_HLEN;
                itfc->min_header_len  += sizeof(xtun_path_s) - ETH_HLEN;
                //
                path->itfc = itfc;
            }
        } else // ALREADY HOOKED
            path->itfc = itfc;

        rtnl_unlock();

        if (path->itfc) { // TODO:
            path->flags |= XTUN_PATH_F_UP_ITFC;
        } else { // TODO: LEMBRAR O NOME ENTÃO - APONTAR PARA O CONFIG?
            printk("XTUN: NODE %u: PATH %u: INTERFACE NOT HOOKED\n", nid, pid);
            dev_put(itfc);
        }
    } else
        printk("XTUN: NODE %u: PATH %u: INTERFACE NOT FOUND\n", nid, pid);
}

static void xtun_print_side (const char* const restrict sideName, const xtun_cfg_node_side_s* const restrict side) {

    printk(" %s MTU %u PKTS %u ",
        sideName, side->mtu, side->pkts);

    switch (side->cryptoAlgo) {
#if      XGW_XTUN_CRYPTO_ALGO_NULL0
        case XTUN_CRYPTO_ALGO_NULL0:
            printk("CRYPTO ALGO NULL0");
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_NULLX
        case XTUN_CRYPTO_ALGO_NULLX:
            printk("CRYPTO ALGO NULLX X 0x%016llX",
                (uintll)side->cryptoParams.nullx.x);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SUM32
        case XTUN_CRYPTO_ALGO_SUM32:
            printk("CRYPTO ALGO SUM32");
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SUM64
        case XTUN_CRYPTO_ALGO_SUM64:
            printk("CRYPTO ALGO SUM64");
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
        case XTUN_CRYPTO_ALGO_SHIFT32_1:
            printk("CRYPTO ALGO SHIFT32_1 KEYS 0x%016llX",
                (uintll)side->cryptoParams.shift32_1.k);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
        case XTUN_CRYPTO_ALGO_SHIFT64_1:
            printk("CRYPTO ALGO SHIFT64_1 KEYS 0x%016llX",
                (uintll)side->cryptoParams.shift64_1.k);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
        case XTUN_CRYPTO_ALGO_SHIFT64_2:
            printk("CRYPTO ALGO SHIFT64_2 KEYS 0x%016llX 0x%016llX",
                (uintll)side->cryptoParams.shift64_2.a,
                (uintll)side->cryptoParams.shift64_2.b);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
        case XTUN_CRYPTO_ALGO_SHIFT64_3:
            printk("CRYPTO ALGO SHIFT64_3 KEYS 0x%016llX 0x%016llX 0x%016llX",
                (uintll)side->cryptoParams.shift64_3.a,
                (uintll)side->cryptoParams.shift64_3.b,
                (uintll)side->cryptoParams.shift64_3.c);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
        case XTUN_CRYPTO_ALGO_SHIFT64_4:
            printk("CRYPTO ALGO SHIFT64_4 KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX",
                (uintll)side->cryptoParams.shift64_4.a,
                (uintll)side->cryptoParams.shift64_4.b,
                (uintll)side->cryptoParams.shift64_4.c,
                (uintll)side->cryptoParams.shift64_4.d);
            break;
#endif
        default:
            printk("CRYPTO ALGO UNKNOWN");
    }
}

static void xtun_node_init (const xtun_cfg_node_s* const cfg, const uint nid) {

    const xtun_cfg_node_side_s* const clt = &cfg->clt;
    const xtun_cfg_node_side_s* const srv = &cfg->srv;
#if XTUN_SERVER
    xtun_node_s* const node = &nodes[nid];
#endif

    printk("XTUN: NODE %u: INITIALIZING WITH NAME %s", nid, cfg->name);

    xtun_print_side("THIS", this);
    xtun_print_side("PEER", peer);

    node->dev           = NULL;
    node->mtu           = this->mtu;
    node->cryptoAlgo    = this->cryptoAlgo;
    node->reserved      = 0;
    node->reserved2     = 0;
    node->flowRemaining = 0;
    node->flowShift     = 0;
    node->flowPackets   = this->pkts;
 // node->flowPackets
 // node->flows
 // node->paths

    memcpy(&node->cryptoParams, &this->cryptoParams, sizeof(xtun_crypto_params_s));

    // INITIALIZE ITS PATHS
    foreach (pid, XTUN_PATHS_N)
        xtun_path_init(node, nid, &node->paths[pid], pid, cfg);
    // INITIALIZE ITS FLOWS
    xtun_node_flows_update(node);

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(XTUN_DEV_PRIV_SIZE, cfg->name, NET_NAME_USER, xtun_dev_setup);

    if (!dev) {
        printk("XTUN: NODE %u: CREATE FAILED - COULD NOT ALLOCATE\n", nid);
        return;
    }

    // INITIALIZE IT, AS WE CAN'T PASS IT TO alloc_netdev()
    dev->mtu             = this->mtu - XTUN_PATH_SIZE_WIRE + ETH_HLEN; // O ETHERNET HEADER NÃO É DESCONTADO NO MTU
    dev->min_mtu         = this->mtu - XTUN_PATH_SIZE_WIRE + ETH_HLEN; //   ...  E ALIÁS, JÁ SERIA COLOCADO UM MESMO
    dev->max_mtu         = this->mtu - XTUN_PATH_SIZE_WIRE + ETH_HLEN;
    XTUN_DEV_NODE(dev)   = node;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        printk("XTUN: NODE %u: CREATE FAILED - COULD NOT REGISTER\n", nid);
        // TODO: LEMBRAR O NOME DA INTERFACE
        free_netdev(dev);
    } else
        node->dev = dev;
}

static int __init xtun_init(void) {

#if XTUN_SERVER
    printk("XTUN: SERVER INIT\n");
#else
    printk("XTUN: CLIENT INIT\n");
#endif

    BUILD_BUG_ON(sizeof(xtun_crypto_params_s) != XTUN_CRYPTO_PARAMS_SIZE);
    BUILD_BUG_ON(sizeof(xtun_path_s) != XTUN_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xtun_node_s) != XTUN_NODE_SIZE);

    // INITIALIZE TUNNELS
    //
#if XTUN_SERVER
    memset(nodes, 0, sizeof(nodes));
#else
    memset(node, 0, sizeof(node));
#endif
    //
    foreach (i, ARRAY_COUNT(cfgNodes))
        xtun_node_init(&cfgNodes[i], cfgNodes[i].id);

    return 0;
}

static void __exit xtun_exit(void) {

}

module_init(xtun_init);
module_exit(xtun_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XTUN");
MODULE_VERSION("0.1");

/*

se for hackear os headers
    atrelar tambem os tcp/udp/udp-lite/sctp/dccp ports ao connection-id


*/