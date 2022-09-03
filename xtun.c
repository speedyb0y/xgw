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

// NOTE: O CLIENTE PRECISA SABER DO SERVIDOR POIS É CONFIGURADO NELE E REPASSADO AO SERVIDOR
#define cltPkts iSize
#define srvPkts uSize

typedef struct xtun_path_s {
    net_device_s* itfc;
#if XTUN_SERVER
    u64 hash; // THE PATH HASH
#else
    u64 reserved2;
#endif
    u32 reserved;
    u16 isUp:1, // ADMINISTRATIVELY
        itfcUp:1, // WATCH INTERFACE EVENTS AND SET THIS
#if XTUN_SERVER
        itfcLearn:1,
        eSrcLearn:1,
        eDstLearn:1,
        iSrcLearn:1,
        iDstLearn:1,    // TODO: TIME DO ULTIMO RECEBIDO; DESATIVAR O PATH NO SERVIDOR SE NAO RECEBER NADA EM TANTO TEMPO
        uDstLearn:1
#endif
        ;
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
    struct xtun_cfg_path_clt_s {
        char itfc[IFNAMSIZ];
        u8 mac[ETH_ALEN];
        u8 gw[ETH_ALEN];
        u8 addr[4];
        u16 port;
        u8 tos;
        u8 ttl;
        uint pkts; // TOTAL DE PACOTES A CADA CIRCULADA
    } clt;
    struct xtun_cfg_path_srv_s {
        char itfc[IFNAMSIZ];
        u8 mac[ETH_ALEN];
        u8 gw[ETH_ALEN];
        u8 addr[4];
        u8 tos;
        u8 ttl;
        uint pkts;
    } srv;
} xtun_cfg_path_s;

typedef struct xtun_cfg_node_s {
    char name[IFNAMSIZ];
    uint mtu;
    xtun_crypto_params_s cryptoParams;
    xtun_crypto_algo_e cryptoAlgo;
    xtun_cfg_path_s paths[XTUN_PATHS_N];
} xtun_cfg_node_s;

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
    { .name = "xgw-0", .mtu = 1500 - 28, .cryptoAlgo = XTUN_CRYPTO_ALGO_NULL0, .paths = {
        {
            .clt = { .itfc = "enp5s0", .pkts =  1000, .mac = MAC(d0,50,99,10,10,10), .gw = MAC(54,9F,06,F4,C7,A0), .addr = {192,168,0,20},    .tos = 0, .ttl = 64, .port = 2000, },
            .srv = { .itfc = "eth0",   .pkts = 11000, .mac = MAC(00,00,00,00,00,00), .gw = MAC(00,00,00,00,00,00), .addr = {200,200,200,200}, .tos = 0, .ttl = 64, },
        }, {
            .clt = { .itfc = "enp5s0", .pkts =  500, .mac = MAC(d0,50,99,11,11,11), .gw = MAC(CC,ED,21,96,99,C0), .addr = {192,168,100,20},  .tos = 0, .ttl = 64, .port = 2111, },
            .srv = { .itfc = "eth0",   .pkts = 4000, .mac = MAC(00,00,00,00,00,00), .gw = MAC(00,00,00,00,00,00), .addr = {200,200,200,200}, .tos = 0, .ttl = 64, },
        }, {
            .clt = { .itfc = "enp5s0", .pkts =  1300, .mac = MAC(d0,50,99,12,12,12), .gw = MAC(90,55,DE,A1,CD,F0), .addr = {192,168,1,20},    .tos = 0, .ttl = 64, .port = 2222 },
            .srv = { .itfc = "eth0",   .pkts = 12000, .mac = MAC(00,00,00,00,00,00), .gw = MAC(00,00,00,00,00,00), .addr = {200,200,200,200}, .tos = 0, .ttl = 64, },
        },
    }},
};

#if XTUN_SERVER
#define mpkts spkts
#else
#define mpkts cpkts
#endif

static void xtun_node_flows_print (const xtun_node_s* const node) {

    char flows[XTUN_FLOWS_N + 1];

    foreach (fid, XTUN_FLOWS_N)
        flows[fid] = '0' + node->flows[fid];
    flows[XTUN_FLOWS_N] = '\0';

    printk("XTUN: TUNNEL %s: PACKETS %u REMAINING %u FLOWS %s\n",
        node->dev->name, node->flowPackets, node->flowRemaining, flows);
}

static void xtun_node_flows_update (xtun_node_s* const node) {

    uintll total = 0;
    uintll maiorB = 0;
    uintll maiorP = 0;

    foreach (pid, XTUN_PATHS_N) {
        const uint b = node->paths[pid].isUp * node->paths[pid].mpkts;
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
            uint q = (node->paths[pid].isUp * ((uintll)node->paths[pid].mpkts) * XTUN_FLOWS_N) / total;
            flowsR -= q;
            while (q--)
                *flows++ = pid;
            pid = (pid + 1) % XTUN_PATHS_N;
        } while (flowsR && pid != maiorP);
    }

    // O QUE SOBRAR DEIXA COM O MAIOR PATH
    while (flowsR--)
        *flows++ = pid;

    //
    if (node->flowPackets != total) {
        node->flowPackets = total;
        node->flowRemaining = 0;
    }
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
     || hdr->iVersion  != 0x45
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
    if (xtun_crypto_decode(node->cryptoAlgo, &node->cryptoParams, payload, payloadSize) != hdr->iHash)
        goto drop;

#if XTUN_SERVER
    // DETECT AND UPDATE PATH CHANGES
    xtun_path_s* const path = &node->paths[pid];

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
        // TODO: MARCAR path->on porque provou que funciona?

        if (path->uDstLearn)
            path->uDst = hdr->uSrc;
        if (path->itfcLearn) // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
            path->itfc = itfc;
        if (path->eSrcLearn)
            memcpy(path->eSrc, hdr->eDst, ETH_ALEN);
        if (path->eDstLearn)
            memcpy(path->eDst, hdr->eSrc, ETH_ALEN);
        if (path->iSrcLearn)
            memcpy(path->iSrc, hdr->iDst, 4);
        if (path->iDstLearn)
            memcpy(path->iDst, hdr->iSrc, 4);

        printk("XTUN: TUNNEL %s: PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s TOS 0x%02X TTL %u\n"
            " SRC %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n"
            " DST %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
            node->dev->name, pid, (uintll)path->hash, path->itfc->name, path->iTOS, path->iTTL,
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

    if (PTR(hdr) < PTR(skb->head))
        goto drop;

    // TODO: FIXME: payloadSize tem que caber no MTU final

    // ENVIA flowPackets, E AÍ AVANCA flowShift
    if (node->flowRemaining == 0) {
        node->flowRemaining = node->flowPackets;
        node->flowShift++;
    } else
        node->flowRemaining--;

    // CHOOSE PATH AND ENCAPSULATE
    memcpy(hdr, &node->paths[node->flows[((u64)node->flowShift + xtun_flow_hash(skb->data)) % XTUN_FLOWS_N]], sizeof(xtun_path_s));

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

    if (!hdr->itfc)
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
    dev->mtu             = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - XTUN_PATH_SIZE_WIRE; // ETH_MAX_MTU
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
#define peer clt
#else
#define this clt
#define peer srv
#endif

static void xtun_path_init (const xtun_node_s* const node, const uint nid, xtun_path_s* const path, const uint pid, const xtun_cfg_path_s* const cfg) {

    printk("XTUN: TUNNEL %s: PATH %u: INITIALIZING\n"
        " CLT PKTS %u ITFC %s MAC %02X:%02X:%02X:%02X:%02X:%02X GW %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u TOS 0x%02X TTL %u\n"
        " SRV PKTS %u ITFC %s MAC %02X:%02X:%02X:%02X:%02X:%02X GW %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u TOS 0x%02X TTL %u\n",
        node->dev->name, pid,
        cfg->clt.pkts, cfg->clt.itfc, _MAC(cfg->clt.mac), _MAC(cfg->clt.gw), _IP4(cfg->clt.addr), cfg->clt.port, cfg->clt.tos, cfg->clt.ttl,
        cfg->srv.pkts, cfg->srv.itfc, _MAC(cfg->srv.mac), _MAC(cfg->srv.gw), _IP4(cfg->srv.addr), PORT(nid, pid), cfg->srv.tos, cfg->srv.ttl
    );

    path->isUp       = 1;
    path->itfc       = NULL;
    path->itfcUp     = 0; // TODO: CAREGAR ISSO NO DEVICE NOTIFIER
#if XTUN_SERVER
    path->hash       = 0;
    path->itfcLearn  = !0;
    path->eSrcLearn  = !0;
    path->eDstLearn  = !0;
    path->iSrcLearn  = !0;
    path->iDstLearn  = !0;
    path->uDstLearn  = !0;
#else
    path->reserved2  = 0;    
#endif
    path->reserved   = 0;    
    path->cltPkts    = cfg->clt.pkts;
    path->srvPkts    = cfg->srv.pkts;
    path->eType      = BE16(ETH_P_IP);
    path->iVersion   = 0x45;
    path->iTOS       = cfg->this.tos;
 // path->iSize
    path->iHash      = 0;
    path->iFrag      = 0;
    path->iTTL       = cfg->this.ttl;
    path->iProtocol  = IPPROTO_UDP;
    path->iCksum     = 0;
#if XTUN_SERVER
    path->uSrc       = BE16(PORT(nid, pid));
    path->uDst       = BE16(cfg->clt.port);
#else
    path->uSrc       = BE16(cfg->clt.port);
    path->uDst       = BE16(PORT(nid, pid));
#endif
 // path->uSize
    path->uCksum     = 0;

    memcpy(path->eSrc, cfg->this.mac, ETH_ALEN);
    memcpy(path->eDst, cfg->this.gw,  ETH_ALEN);

    memcpy(path->iSrc, cfg->this.addr, 4);
    memcpy(path->iDst, cfg->peer.addr, 4);

    net_device_s* const itfc = dev_get_by_name(&init_net, cfg->this.itfc);

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

        if (!path->itfc) {
            printk("XTUN: TUNNEL %s: PATH %u: HOOK: FAILED\n",
                node->dev->name, pid);
            dev_put(itfc);
        }
    } else
        printk("XTUN: TUNNEL %s: PATH %u: HOOK: INTERFACE NOT FOUND\n",
            node->dev->name, pid);
}

static void xtun_node_init (xtun_node_s* const node, const uint nid, const xtun_cfg_node_s* const cfg) {

    printk("XTUN: TUNNEL %s: NODE #%u INITIALIZING WITH MTU %u",
        cfg->name, nid, cfg->mtu);

    switch (cfg->cryptoAlgo) {
#if      XGW_XTUN_CRYPTO_ALGO_NULL0
        case XTUN_CRYPTO_ALGO_NULL0:
            printk("CRYPTO ALGO NULL0");
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_NULLX
        case XTUN_CRYPTO_ALGO_NULLX:
            printk("CRYPTO ALGO NULLX X 0x%016llX",
                (uintll)cfg->cryptoParams.nullx.x);
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
                (uintll)cfg->cryptoParams.shift32_1.k);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
        case XTUN_CRYPTO_ALGO_SHIFT64_1:
            printk("CRYPTO ALGO SHIFT64_1 KEYS 0x%016llX",
                (uintll)cfg->cryptoParams.shift64_1.k);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
        case XTUN_CRYPTO_ALGO_SHIFT64_2:
            printk("CRYPTO ALGO SHIFT64_2 KEYS 0x%016llX 0x%016llX",
                (uintll)cfg->cryptoParams.shift64_2.a,
                (uintll)cfg->cryptoParams.shift64_2.b);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
        case XTUN_CRYPTO_ALGO_SHIFT64_3:
            printk("CRYPTO ALGO SHIFT64_3 KEYS 0x%016llX 0x%016llX 0x%016llX",
                (uintll)cfg->cryptoParams.shift64_3.a,
                (uintll)cfg->cryptoParams.shift64_3.b,
                (uintll)cfg->cryptoParams.shift64_3.c);
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
        case XTUN_CRYPTO_ALGO_SHIFT64_4:
            printk("CRYPTO ALGO SHIFT64_4 KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX",
                (uintll)cfg->cryptoParams.shift64_4.a,
                (uintll)cfg->cryptoParams.shift64_4.b,
                (uintll)cfg->cryptoParams.shift64_4.c,
                (uintll)cfg->cryptoParams.shift64_4.d);
            break;
#endif
        default:
            printk("CRYPTO ALGO UNKNOWN");
    }

    node->dev           = NULL;
    node->mtu           = cfg->mtu;
    node->cryptoAlgo    = cfg->cryptoAlgo;
    node->reserved      = 0;
    node->reserved2     = 0;
    node->flowRemaining = 0;
    node->flowShift     = 0;
 // node->flowPackets
 // node->flows
 // node->paths
 
    memcpy(&node->cryptoParams, &cfg->cryptoParams, sizeof(xtun_crypto_params_s));

    // INITIALIZE ITS PATHS
    foreach (pid, XTUN_PATHS_N)
        xtun_path_init(node, nid,
            &node->paths[pid], pid,
             &cfg->paths[pid]);

    // INITIALIZE ITS FLOWS
    xtun_node_flows_update(node);
    xtun_node_flows_print(node);

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(XTUN_DEV_PRIV_SIZE, cfg->name, NET_NAME_USER, xtun_dev_setup);

    if (!dev) {
        printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT ALLOCATE\n", cfg->name);
        return;
    }

    // INITIALIZE IT, AS WE CAN'T PASS IT TO alloc_netdev()
    XTUN_DEV_NODE(dev) = node;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT REGISTER\n", cfg->name);
        // TODO: LEMBRAR O NOME DA INTERFACE
        free_netdev(dev);
    } else
        node->dev = dev;
}

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_crypto_params_s) != XTUN_CRYPTO_PARAMS_SIZE);
    BUILD_BUG_ON(sizeof(xtun_path_s) != XTUN_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xtun_node_s) != XTUN_NODE_SIZE);

    // INITIALIZE TUNNELS
#if XTUN_SERVER
    foreach (nid, XTUN_NODES_N)
        xtun_node_init(&nodes[nid], nid, &cfgNodes[nid]);
#else
        xtun_node_init(node, XTUN_NODE_ID, cfgNode);
#endif

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
