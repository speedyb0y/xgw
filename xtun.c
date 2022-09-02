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

static inline u8  BE8 (u8  x) { return                   x;  }
static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define __MAC(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
#define __IP4(x) (x)[0], (x)[1], (x)[2], (x)[3]

#define _MAC(x) __MAC((u8*)(x))
#define _IP4(x) __IP4((u8*)(x))

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

#include "xtun-encoding.c"

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
#define XTUN_DEV_NODE(dev) (*(xtun_node_s**)netdev_priv(dev))
#else
#define XTUN_DEV_NODE(dev) ((dev)->rx_handler_data)
#endif

// EXPECTED SIZE
#define XTUN_PATH_SIZE CACHE_LINE_SIZE
#define XTUN_PATH_SIZE_PRIVATE (XTUN_PATH_SIZE - XTUN_PATH_SIZE_WIRE)
#define XTUN_PATH_SIZE_WIRE (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE)

#define PATH_ETH(path) PTR(&(path)->eDst)
#define PATH_IP(path)  PTR(&(path)->iVersion)
#define PATH_UDP(path) PTR(&(path)->uSrc)

typedef struct xtun_path_s {
    net_device_s* itfc;
#if XTUN_SERVER
    u64 hash; // THE PATH HASH
#else
    u32 seila;
    u32 cband;
#endif
    u32 sband;
    u16 qband;
#define ETH_HDR_SIZE 14
    u16 eDst[3];
    u16 eSrc[3];
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
    u32 iSrc;
    u32 iDst;
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
    u64 keys[XTUN_KEYS_N];
    u64 reserved2;
    u32 reserved;
    u16 iHash;
    u16 flowShift; // SHIFTA TODOS OS FLOW IDS AO MESMO TEMPO, AO SELECIONAR O PATH
    u32 flowRemaining; // QUANTOS PACOTES ENVIAR ATÉ AVANÇAR O FLOW SHIFT
    u32 flowPackets; // O QUE USAR COMO FLOW REMAINING
    u8  flows[XTUN_FLOWS_N]; // MAPA FLOW ID -> PATH ID
    xtun_path_s paths[XTUN_PATHS_N];
} xtun_node_s;

typedef struct xtun_cfg_path_s {
    u32 cband;
    u32 sband;
    char itfc[IFNAMSIZ];
    union { u8 cmac[8]; u16 cmac16[3]; };
    union { u8 smac[8]; u16 smac16[3]; };
    union { u8 caddr[sizeof(u32)]; u32 caddr32; };
    union { u8 saddr[sizeof(u32)]; u32 saddr32; };
    u16 cport;
    u8 tos;
    u8 ttl;
} xtun_cfg_path_s;

typedef struct xtun_cfg_node_s {
    const char name[IFNAMSIZ];
    u16 iHash;
    u32 flowPackets; // TOTAL DE PACOTES A CADA CIRCULADA
    u64 keys[XTUN_KEYS_N];
    xtun_cfg_path_s paths[XTUN_PATHS_N];
} xtun_cfg_node_s;

static const char* const itfcs[] = { "enp5s0" };

#if XTUN_SERVER
static xtun_node_s nodes[XTUN_NODES_N];
#else
static xtun_node_s node[1];
#endif

#if XTUN_SERVER
static const xtun_cfg_node_s cfgNodes[XTUN_NODES_N] =
#else
static const xtun_cfg_node_s cfgNode[1] =
#endif
{
    { .name = "xgw-0", .iHash = 0x2562, .keys = { 0, 0, 0, 0 }, .flowPackets = 32*1000, .paths = {
        { .itfc = "enp5s0", .cband = 60, .sband = 480, .tos = 0, .ttl = 64,
            .cmac = MAC(d0,50,99,10,10,10), .caddr = {192,168,0,20},    .cport = 2000,
            .smac = MAC(54,9F,06,F4,C7,A0), .saddr = {200,200,200,200}
        },
        { .itfc = "enp5s0", .cband = 40, .sband = 80, .tos = 0, .ttl = 64,
            .cmac = MAC(d0,50,99,11,11,11), .caddr = {192,168,100,20},  .cport = 2111,
            .smac = MAC(CC,ED,21,96,99,C0), .saddr = {200,200,200,200}
        },
        { .itfc = "enp5s0", .cband = 90, .sband = 590, .tos = 0, .ttl = 64,
            .cmac = MAC(d0,50,99,12,12,12), .caddr = {192,168,1,20},    .cport = 2222,
            .smac = MAC(90,55,DE,A1,CD,F0), .saddr = {200,200,200,200}
        },
    }},
};

#if XTUN_SERVER
#define mband sband
#else
#define mband cband
#endif

static void xtun_node_flows_print (const xtun_node_s* const node) {

    char flows[XTUN_FLOWS_N + 1];

    foreach (fid, XTUN_FLOWS_N)
        flows[fid] = '0' + node->flows[fid];
    flows[XTUN_FLOWS_N] = '\0';

    printk("XTUN: TUNNEL %s: FLOWS: %s\n",
        node->dev->name, flows);
}

static void xtun_node_flows_update (xtun_node_s* const node) {

    uintll total = 0;
    uintll maiorB = 0;
    uintll maiorP = 0;

    foreach (pid, XTUN_PATHS_N) {
        const uint b = node->paths[pid].mband;
        // CALCULA O TOTAL
        total += b;
        // LEMBRA O PATH COM MAIOR BANDWIDTH
        // LEMBRA O BANDWIDTH DELE
        if (maiorB < b) {
            maiorB = b;
            maiorP = pid;
        }
    }

    u8* flows = node->flows;
    uint flowsR = XTUN_FLOWS_N;
    uint pid = maiorP;

    if (total) {
        do {
            uint q = (((uintll)node->paths[pid].mband) * XTUN_FLOWS_N) / total;
            flowsR -= q;
            while (q--)
                *flows++ = pid;
            pid = (pid + 1) % XTUN_PATHS_N;
        } while (flowsR && pid != maiorP);
    }

    // O QUE SOBRAR DEIXA COM O MAIOR PATH
    while (flowsR--)
        *flows++ = pid;
}

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    const xtun_path_s* const hdr = PTR(skb->data) + IP4_HDR_SIZE + UDP_HDR_SIZE - sizeof(xtun_path_s);

    XTUN_ASSERT(!skb->data_len);
    XTUN_ASSERT(PTR(skb_network_header(skb)) == skb->data);
    XTUN_ASSERT((PTR(skb_network_header(skb)) + skb->len) == SKB_TAIL(skb));
    XTUN_ASSERT(PTR(hdr) >= PTR(skb->head));
    XTUN_ASSERT((PTR(hdr) + sizeof(xtun_path_s)) <= SKB_TAIL(skb));

    // IDENTIFY NODE AND PATH IDS FROM SERVER PORT
#if XTUN_SERVER
    const uint port = BE16(hdr->uDst);
#else
    const uint port = BE16(hdr->uSrc);
#endif
    const uint nid = PORT_NID(port);
    const uint pid = PORT_PID(port);

    // CONFIRM PACKET SIZE
    // IGNORE NON-LINEAR SKB
    // CONFIRM THIS IS ETHERNET/IPV4/UDP
    // VALIDATE NODE ID
    // VALIDATE PATH ID
    if (skb->len <= XTUN_PATH_SIZE_WIRE
     || skb->data_len
     || hdr->eType     != BE16(ETH_P_IP)
     || hdr->iVersion  != BE8(0x45)
     || hdr->iProtocol != BE8(IPPROTO_UDP)
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

    // DROP EMPTY PAYLOADS
    // DROP INCOMPLETE PAYLOADS
    if ((payloadSize == 0) || (payload + payloadSize) > SKB_TAIL(skb))
        goto drop;

    // DECRYPT AND CONFIRM AUTHENTICITY
    if (node->iHash) { // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
        if (node->iHash != hdr->iHash)
            goto drop;
    } elif (xtun_decode(node->keys, payload, payloadSize) != hdr->iHash)
        goto drop;

#if XTUN_SERVER
    // DETECT AND UPDATE PATH CHANGES
    xtun_path_s* const path = &node->paths[pid];

    net_device_s* const itfc = skb->dev;

    const u64 hash = (u64)(uintptr_t)itfc
      + ((u64)hdr->eDst[0] <<  0)
      + ((u64)hdr->eDst[1] <<  4)
      + ((u64)hdr->eDst[2] <<  8)
      + ((u64)hdr->eSrc[0] << 12)
      + ((u64)hdr->eSrc[1] << 16)
      + ((u64)hdr->eSrc[2] << 20)
      + ((u64)hdr->iSrc    << 24)
      + ((u64)hdr->iDst    << 28)
      + ((u64)hdr->uSrc    << 32)
    ;

    if (path->hash != hash) {
        path->hash    = hash;
        path->itfc    = itfc;
        path->eDst[0] = hdr->eSrc[0];
        path->eDst[1] = hdr->eSrc[1];
        path->eDst[2] = hdr->eSrc[2];
        path->eSrc[0] = hdr->eDst[0];
        path->eSrc[1] = hdr->eDst[1];
        path->eSrc[2] = hdr->eDst[2];
        path->iSrc    = hdr->iDst;
        path->iDst    = hdr->iSrc;
        path->uDst    = hdr->uSrc;

        printk("XTUN: TUNNEL %s: PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s TOS 0x%02X TTL %u"
            " CLT MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u"
            " SRV MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n",
            node->dev->name, pid, (uintll)path->hash, path->itfc->name, BE8(path->iTOS), BE8(path->iTTL),
            _MAC(path->eSrc), _IP4((u8*)&path->iSrc), BE16(path->uSrc),
            _MAC(path->eDst), _IP4((u8*)&path->iDst), BE16(path->uDst)
        );
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

static u64 xtun_flow_hash (const void* const flow) {

    u64 hash = BE8(*(u8*)flow) >> 4;

    if (hash == 4) {
        // IPV4
        hash = BE8(*(u8*)(flow + 9));
        if (hash == IPPROTO_TCP
         || hash == IPPROTO_UDP
         || hash == IPPROTO_UDPLITE
         || hash == IPPROTO_SCTP
         || hash == IPPROTO_DCCP)
            hash += *(u32*)(flow + (BE8(*(u8*)flow) & 0x0F)*4);
        hash += *(u64*)(flow + 12);
    } elif (hash == 6) {
        // IPV6
        hash = BE8(*(u8*)(flow + 6));
        if (hash == IPPROTO_TCP
         || hash == IPPROTO_UDP
         || hash == IPPROTO_UDPLITE
         || hash == IPPROTO_SCTP
         || hash == IPPROTO_DCCP)
            hash += *(u32*)(flow + 40);
        hash += *(u64*)(flow + 8);
        hash += *(u64*)(flow + 16);
        hash += *(u64*)(flow + 24);
        hash += *(u64*)(flow + 32);
    } else
        // UNKNOWN
        hash = 0;

    hash += hash >> 32;
    hash += hash >> 16;

    return hash;
}

static netdev_tx_t xtun_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    // ASSERT: skb->len <= xtun->mtu
    // ASSERT: skb->len <= xtun->dev->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER
    // ASSERT: skb->len <= xtun->path->itfc->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER

    void* const payload = skb->data;
    const uint payloadSize = skb->len;

    xtun_path_s* const hdr = PTR(payload) - sizeof(xtun_path_s);
    xtun_node_s* const node = XTUN_DEV_NODE(dev);

    XTUN_ASSERT(!skb->data_len);
    XTUN_ASSERT(!skb->mac_len);
    XTUN_ASSERT(PTR(payload) == PTR(skb_mac_header(skb)));
    XTUN_ASSERT(PTR(payload) == PTR(skb_network_header(skb)));
    XTUN_ASSERT((PTR(payload) + payloadSize) == SKB_TAIL(skb));
    XTUN_ASSERT(PTR(hdr) >= PTR(skb->head));

    // ENVIA flowPackets, E AÍ AVANCA flowShift
    if (node->flowRemaining == 0) {
        node->flowRemaining = node->flowPackets;
        node->flowShift++;
    } else
        node->flowRemaining--;

    // CHOOSE PATH AND ENCAPSULATE
    memcpy(hdr, &node->paths[node->flows[((u64)node->flowShift + xtun_flow_hash(skb->data)) % XTUN_FLOWS_N]], sizeof(xtun_path_s));

    // ENCRYPT AND AUTHENTIFY
    if (node->iHash)
        hdr->iHash = node->iHash;
    else
        hdr->iHash = xtun_encode(node->keys, payload, payloadSize);

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

    if (hdr->itfc) {
        skb->dev = hdr->itfc; // TODO: AO TROCAR TEM QUE DAR dev_put(skb->dev) ?
        // THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
        // WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
        dev_queue_xmit(skb);
    } else
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
    dev->mtu             = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_MAX_MTU
    dev->addr_len        = 0;
    dev->tx_queue_len    = 0; // EFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
                        // IFF_NO_RX_HANDLER?
        ;
}

static void xtun_path_init (const xtun_node_s* const node, const uint nid, xtun_path_s* const path, const uint pid, const xtun_cfg_path_s* const cfg) {

    printk("XTUN: TUNNEL %s: PATH %u: INITIALIZING WITH ITFC %s TOS 0x%02X TTL %u"
        " CLT BAND %u MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u"
        " SRV BAND %u MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n",
        node->dev->name, pid, cfg->itfc, cfg->tos, cfg->ttl,
        cfg->cband, _MAC(cfg->cmac), _IP4(&cfg->caddr), cfg->cport,
        cfg->sband, _MAC(cfg->smac), _IP4(&cfg->saddr), PORT(nid, pid)
    );

    path->itfc       =  NULL;
#if XTUN_SERVER
    path->hash       =  0;
    path->sband      =  cfg->sband;
    path->eDst[0]    =  0;
    path->eDst[1]    =  0;
    path->eDst[2]    =  0;
    path->eSrc[0]    =  0;
    path->eSrc[1]    =  0;
    path->eSrc[2]    =  0;
#else
    path->seila      =  0;
    path->cband      =  cfg->cband;
    path->sband      =  cfg->sband;
    path->eDst[0]    =  cfg->smac16[0];
    path->eDst[1]    =  cfg->smac16[1];
    path->eDst[2]    =  cfg->smac16[2];
    path->eSrc[0]    =  cfg->cmac16[0];
    path->eSrc[1]    =  cfg->cmac16[1];
    path->eSrc[2]    =  cfg->cmac16[2];
#endif
    path->eType      =  BE16(ETH_P_IP);
    path->iVersion   =  0x45;
    path->iTOS       =  cfg->tos;
    path->iSize      =  0;
    path->iHash      =  0;
    path->iFrag      =  0;
    path->iTTL       =  cfg->ttl;
    path->iProtocol  =  IPPROTO_UDP;
    path->iCksum     =  0;
#if XTUN_SERVER
    path->iSrc       =  0;
    path->iDst       =  0;
    path->uSrc       =  BE16(PORT(nid, pid));
    path->uDst       =  0;
#else
    path->iSrc       =  cfg->caddr32;
    path->iDst       =  cfg->saddr32;
    path->uSrc       =  BE16(cfg->cport);
    path->uDst       =  BE16(PORT(nid, pid));
#endif
    path->uSize      =  0;
    path->uCksum     =  0;

#if !XTUN_SERVER
    net_device_s* const itfc = dev_get_by_name(&init_net, cfg->itfc);

    if (itfc) {
        // THE HOOK OWNS IT
        dev_put(itfc);
        //
        if (itfc->rx_handler == xtun_in)
            path->itfc  = itfc;
        else
            printk("XTUN: TUNNEL %s: PATH %u: CREATE FAILED - INTERFACE NOT HOOKED\n", node->dev->name, pid);
    } else
        printk("XTUN: TUNNEL %s: PATH %u: CREATE FAILED - INTERFACE NOT FOUND\n", node->dev->name, pid);
#endif
}

static void xtun_node_init (xtun_node_s* const node, const uint nid, const xtun_cfg_node_s* const cfg) {

    printk("XTUN: TUNNEL %s: NODE #%u INITIALIZING WITH"
        " IHASH 0x%04X KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX FLOW PACKETS %llu"
        "\n",
        cfg->name, nid, cfg->iHash,
        (uintll)cfg->keys[0],
        (uintll)cfg->keys[1],
        (uintll)cfg->keys[2],
        (uintll)cfg->keys[3],
        (uintll)cfg->flowPackets
    );

    node->iHash         = cfg->iHash;
    node->keys[0]       = cfg->keys[0];
    node->keys[1]       = cfg->keys[1];
    node->keys[2]       = cfg->keys[2];
    node->keys[3]       = cfg->keys[3];
    node->flowPackets   = cfg->flowPackets;
    node->flowRemaining = 0;
    node->flowShift     = 0;

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(sizeof(xtun_node_s*), cfg->name, NET_NAME_USER, xtun_dev_setup);

    if (!dev) {
        printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT ALLOCATE\n", cfg->name);
        return;
    }

    // INITIALIZE IT, AS WE CAN'T PASS IT TO alloc_netdev()
    XTUN_DEV_NODE((node->dev = dev)) = node;

    foreach (pid, XTUN_PATHS_N)
        xtun_path_init(node, nid,
            &node->paths[pid], pid,
             &cfg->paths[pid]);

    xtun_node_flows_update(node);
    xtun_node_flows_print(node);

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT REGISTER\n", cfg->name);
        node->dev = NULL; // TODO: LEMBRAR O NOME DA INTERFACE
        free_netdev(dev);
    }
}

// INITIALIZE TUNNELS
static void xtun_nodes_init (void) {

#if XTUN_SERVER
    foreach (nid, XTUN_NODES_N)
        xtun_node_init(&nodes[nid], nid, &cfgNodes[nid]);
#else
        xtun_node_init(node, XTUN_NODE_ID, cfgNode);
#endif
}

// HOOK INTERFACES
static void xtun_itfcs_hook (void) {

    foreach (i, ARRAY_COUNT(itfcs)) {

        const char* const itfc = itfcs[i];

        net_device_s* dev;

        if (!(dev = dev_get_by_name(&init_net, itfc))) {
            printk("XTUN: INTERFACE %s: HOOK: COULD NOT FIND\n", itfc);
            continue;
        }

        rtnl_lock();

        // NOTE: WE ARE SUPPORTING SAME INTERFACE MULTIPLE TIMES
        if (rcu_dereference(dev->rx_handler) != xtun_in) {
            // NOT HOOKED YET
            if (!netdev_rx_handler_register(dev, xtun_in, NULL)) {
                // NOW IT'S HOOKED
                // TODO: FIXME: TEM QUE FAZER ISSO EM TODAS AS INTERFACES OU NAO VAI PODER CONSIDERAR O SKB COMO xtun_path_s
                printk("XTUN: INTERFACE %s: HOOK: SUCCESS\n", itfc);
                dev->hard_header_len += sizeof(xtun_path_s) - ETH_HLEN; // A INTERFACE JA TEM O ETH_HLEN
                dev->min_header_len  += sizeof(xtun_path_s) - ETH_HLEN;
                dev = NULL;
            } else
                printk("XTUN: INTERFACE %s: HOOK: FAILED\n", itfc);
        } else { // ALREADY HOOKED, BUT REFERENCED ANOTHER TIME
            printk("XTUN: INTERFACE %s: HOOK: ALREADY\n", itfc);
            dev = NULL;
        }

        rtnl_unlock();

        if (dev)
            dev_put(dev);
    }
}

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_path_s) != XTUN_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xtun_node_s) != XTUN_NODE_SIZE);

    xtun_itfcs_hook();

    xtun_nodes_init();

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
