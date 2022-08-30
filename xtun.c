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
#define XTUN_ASSERT(c) if (!(c)) { printk("ASSERT FAILED: " #c "\n"); }
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

static inline u8  BE8 (u8  x) { return                   x;  }
static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define XTUN_SERVER_PORT XGW_XTUN_SERVER_PORT

#define NODES_N 1
#define PATHS_N 3

#define PORT(nid, pid) (XTUN_SERVER_PORT + (nid)*10 + (pid))

// WILL UNSIGNED OVERFLOW IF LOWER
#define PORT_NID(port) (((port) - XTUN_SERVER_PORT) / 10)
#define PORT_PID(port) (((port) - XTUN_SERVER_PORT) % 10)

// EXPECTED SIZE
#define XTUN_PATH_SIZE CACHE_LINE_SIZE

#define XTUN_PATH_SIZE_ALL (XTUN_PATH_SIZE_PRIVATE + XTUN_PATH_SIZE_ETH)
#define XTUN_PATH_SIZE_PRIVATE   (sizeof(net_device_s*) + sizeof(u64) + sizeof(u32) + sizeof(u16))
#define XTUN_PATH_SIZE_ETH       (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_PATH_SIZE_IP        (               IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_PATH_SIZE_UDP       (                              UDP_HDR_SIZE)

typedef struct xtun_path_s {
    net_device_s* phys;
#if XGW_XTUN_SERVER_IS
    u64 hash; // THE PATH HASH
#else
    u32 seila;
    u32 bandSrv; // BANDA DO SERVIDOR, A REPASSAR A ELE; INTERVALO DE ENVIO DISSO/AUTH
#endif
    u32 band;
    u16 reserved;
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
    u16 uDst; // THE SERVER PORT WILL DETERMINE THE NODE AND PATH
    u16 uSize;
    u16 uCksum;
} xtun_path_s;

typedef struct xtun_node_s {
    net_device_s* dev; // TUNNEL VIRTUAL INTERFACE DEVICE
    u64 remaining;
    u64 secret; // COMUM ENTRE AMBAS AS PARTES, NUNCA REPASSADO
    u64 key; // DINAMICO, GERADO PELO CLIENTE
    xtun_path_s paths[PATHS_N];
} xtun_node_s;

#define __MAC(a,b,c) a ## b ## c
#define _MAC(x) __MAC(0x,x,U)
#define MAC(a,b,c,d,e,f) { _MAC(a), _MAC(b), _MAC(c), _MAC(d), _MAC(e), _MAC(f) }

typedef struct xtun_cfg_path_s {
    const char phys[IFNAMSIZ];
    union { u8 cltMAC[8]; u16 cltMAC16[4]; };
    union { u8 srvMAC[8]; u16 srvMAC16[4]; };
    union { u8 cltAddr[4]; u32 cltAddr32; };
    union { u8 srvAddr[4]; u32 srvAddr32; };
    u16 cltPort;
    u8  iTOS;
    u8  iTTL;
    u16 band;
#if !XGW_XTUN_SERVER_IS
    u32 seila;
    u32 bandSrv;
#endif
} xtun_cfg_path_s;

typedef struct xtun_cfg_node_s {
    const char name[IFNAMSIZ];
    u64 secret;
    xtun_cfg_path_s paths[PATHS_N];
} xtun_cfg_node_s;

static xtun_node_s nodes[NODES_N];

static const xtun_cfg_node_s cfgs[NODES_N] = {
    { .name = "xgw-0", .secret = 0, .paths = {
        { .phys = "isp-0", .iTOS = 0, .iTTL = 64,
            .cltMAC = MAC(d0,50,99,10,10,10), .cltAddr = {192,168,0,20},    .cltPort = 2000,
            .srvMAC = MAC(54,9F,06,F4,C7,A0), .srvAddr = {200,200,200,200}
        },
        { .phys = "isp-1", .iTOS = 0, .iTTL = 64,
            .cltMAC = MAC(d0,50,99,11,11,11), .cltAddr = {192,168,100,20},  .cltPort = 2111,
            .srvMAC = MAC(CC,ED,21,96,99,C0), .srvAddr = {200,200,200,200}
        },
        { .phys = "isp-2", .iTOS = 0, .iTTL = 64,
            .cltMAC = MAC(d0,50,99,12,12,12), .cltAddr = {192,168,1,20},    .cltPort = 2222,
            .srvMAC = MAC(90,55,DE,A1,CD,F0), .srvAddr = {200,200,200,200}
        },
    }},
};

#include "xtun-encoding.c"
#include "xtun-auth.c"

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    const xtun_path_s* const hdr = PTR(skb_mac_header(skb)) - XTUN_PATH_SIZE_PRIVATE;

    void* const payload = PTR(hdr) + sizeof(*hdr);

    //XTUN_ASSERT(skb->dev != virt);
    XTUN_ASSERT(PTR(hdr->eDst) >= PTR(skb->head));
    // ASSERT: (PTR(skb_mac_header(skb)) + skb->len) == skb->tail
    XTUN_ASSERT(skb->protocol == hdr->eType);
    //XTUN_ASSERT(payload <= skb->end);

    // TODO: FIXME: VAI TER QUE CONSIDERAR AMBOS OS CABECALHOS E O SKB PORQUE PODE TER UM LIXO ALI
    const uint payloadSize = SKB_TAIL(skb) - payload;

#if XGW_XTUN_SERVER_IS
    const uint srvPort = BE16(hdr->uDst);
#else
    const uint srvPort = BE16(hdr->uSrc);
#endif
    const uint nid = PORT_NID(srvPort);
    const uint pid = PORT_PID(srvPort);

    xtun_node_s* const node = &nodes[nid];

    if (skb->len < XTUN_PATH_SIZE_ETH
     || hdr->eType     != BE16(ETH_P_IP)
     || hdr->iVersion  != BE8(0x45)
     || hdr->iProtocol != BE8(IPPROTO_UDP)
     || nid >= NODES_N
     || pid >= PATHS_N
     || !node->dev)
        // NOT UDP/IPV4/ETHERNET
        // WE DON'T HAVE THIS TUNNEL/PATH
        goto pass;

    if (hdr->iHash) {
        // NOT AUTH
        if (xtun_decode(node->secret, node->key, payload, payloadSize) != hdr->iHash)
            // HASH MISMATCH
            goto drop;
    } else {
        // AUTH
#if XGW_XTUN_SERVER_IS
        if (skb->len != (XTUN_PATH_SIZE_ETH + XTUN_AUTH_SIZE))
            // INVALID AUTH SIZE
            goto drop;
        const u16 key = xtun_auth_key_check(node->secret, payload);
        if (!key)
            // INCORRECT AUTH
            goto drop;
        // USA ELA
        node->key = key;
#else // UNEXPECTED AUTH FROM SERVER
        goto drop;
#endif
    }

#if XGW_XTUN_SERVER_IS
    // DETECT AND UPDATE PATH CHANGES

    xtun_path_s* const path = &node->paths[pid];

    net_device_s* const dev = skb->dev;

    const u64 hash = (u64)(uintptr_t)dev
      + ((u64)hdr->eDst[0] <<  0)
      + ((u64)hdr->eDst[1] <<  4)
      + ((u64)hdr->eDst[2] <<  8)
      + ((u64)hdr->eSrc[0] << 12)
      + ((u64)hdr->eSrc[1] << 16)
      + ((u64)hdr->eSrc[2] << 20)
      + ((u64)hdr->iSrc    << 24)
      + ((u64)hdr->iDst    << 28)
      + ((u64)hdr->uSrc    << 32)
      + ((u64)hdr->uDst    << 36)
    ;

    if (path->hash != hash) {

        printk("XTUN: TUNNEL %s: UPDATING PATH\n", node->dev->name);

        if (path->phys != dev) {
            if (path->phys)
                dev_put(path->phys);
            dev_hold(dev);
        }

        path->hash    = hash;
        path->phys    = dev;
        path->eDst[0] = hdr->eSrc[0];
        path->eDst[1] = hdr->eSrc[1];
        path->eDst[2] = hdr->eSrc[2];
        path->eSrc[0] = hdr->eDst[0];
        path->eSrc[1] = hdr->eDst[1];
        path->eSrc[2] = hdr->eDst[2];
        path->iSrc    = hdr->iDst;
        path->iDst    = hdr->iSrc;
        // NOTE: NOSSA PORTA NÃO É ATUALIZADA AQUI:
        //      A PORTA DO SERVIDOR É ESTÁVEL
        //      A PORTA DO CLIENTE É ELE QUE MUDA
        // TANTO QUE NEM VAI CHEGAR ATÉ AQUI SE NÃO FOR PARA A PORTA ATUAL
      //path->uSrc    = hdr->uDst;
        path->uDst    = hdr->uSrc;
    }

    if (!hdr->iHash)
        // ERA UM AUTH, SO QUIS ATUALIZAR O PATH
        goto drop;
#endif

    // DESENCAPSULA
    skb->mac_len          = 0;
    skb->data             = payload;
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = payload - PTR(skb->head);
    skb->len             -= XTUN_PATH_SIZE_ETH;
    skb->dev              = node->dev;
    skb->protocol         = hdr->eType;

pass:
    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xtun_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    // ASSERT: skb->len <= xtun->mtu
    // ASSERT: skb->len <= xtun->virt->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER
    // ASSERT: skb->len <= xtun->phys->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER

    // ENCAPSULATE
    xtun_path_s* const pkt = PTR(skb->data) - sizeof(xtun_path_s);

    xtun_node_s* const node = *(xtun_node_s**)netdev_priv(dev);

    const uint pid = 0;

    xtun_path_s* const path = &node->paths[pid]; // TODO: FIXME:

    // ASSERT: PTR(skb_mac_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(skb_network_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(pkt) >= PTR(skb->head)

    memcpy(pkt, path, sizeof(xtun_path_s));

    pkt->uSize  = BE16(skb->len + XTUN_PATH_SIZE_UDP);
    pkt->iSize  = BE16(skb->len + XTUN_PATH_SIZE_IP);
    pkt->iCksum = ip_fast_csum((void*)pkt, 5);

    skb->transport_header = PTR(&pkt->uSrc)     - PTR(skb->head);
    skb->network_header   = PTR(&pkt->iVersion) - PTR(skb->head);
    skb->mac_header       = PTR(&pkt->eDst)     - PTR(skb->head);
    skb->data             = PTR(&pkt->eDst);
    skb->len             += XTUN_PATH_SIZE_ETH;
    skb->protocol         = BE16(ETH_P_IP);
    skb->ip_summed        = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
    skb->mac_len          = ETH_HLEN;

    if (pkt->phys) {
        skb->dev = pkt->phys; // TODO: AO TROCAR TEM QUE DAR dev_put(skb->dev) ?
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
    dev->hard_header_len = XTUN_PATH_SIZE_ETH; // ETH_HLEN
    dev->min_header_len  = XTUN_PATH_SIZE_ETH;
    dev->mtu             = 1500 - 28 - XTUN_PATH_SIZE_ETH; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - XTUN_PATH_SIZE_ETH; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - XTUN_PATH_SIZE_ETH; // ETH_MAX_MTU
    dev->addr_len        = 0;
    dev->tx_queue_len    = 0; // EFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
                        // IFF_NO_RX_HANDLER?
        ;
}

#define _A6(x) x[0], x[1], x[2], x[3], x[4], x[5]
#define _A4(x) x[0], x[1], x[2], x[3]

#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))

static const char* const itfcs[] = { "eth0" };

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_path_s) != XTUN_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xtun_path_s) != XTUN_PATH_SIZE_ALL);
    BUILD_BUG_ON(sizeof(xtun_auth_s) != XTUN_AUTH_SIZE);

    // HOOK INTERFACES
    for (uint i = 0; i != ARRAY_COUNT(itfcs); i++) {

        const char* const itfc = itfcs[i];

        net_device_s* dev;

        if (!(dev = dev_get_by_name(&init_net, itfc))) {
            printk("XTUN: INTERFACE %s: COULD NOT FIND\n", itfc);
            continue;
        }

        rtnl_lock();

        // NOTE: WE ARE SUPPORTING SAME INTERFACE MULTIPLE TIMES
        if (dev->rx_handler != xtun_in) {
            // NOT HOOKED YET
            if (!netdev_rx_handler_register(dev, xtun_in, NULL)) {
                // NOW IT'S HOOKED
                // TODO: FIXME: TEM QUE FAZER ISSO EM TODAS AS INTERFACES OU NAO VAI PODER CONSIDERAR O SKB COMO xtun_path_s
                printk("XTUN: INTERFACE %s: HOOKED\n", itfc);
                dev->hard_header_len += sizeof(xtun_path_s) - ETH_HLEN; // A INTERFACE JA TEM O ETH_HLEN
                dev->min_header_len  += sizeof(xtun_path_s) - ETH_HLEN;
                dev = NULL;
            }
        } else
            // ALREADY HOOKED
            dev = NULL;

        rtnl_unlock();

        if (dev)
            dev_put(dev);
    }

    // INITIALIZE TUNNELS
    memset(nodes, 0, sizeof(nodes));

    for (uint nid = 0; nid != NODES_N; nid++) {

        const xtun_cfg_node_s* const cfgNode = &cfgs[nid];

        printk("XTUN: TUNNEL %s: NODE #%u INITIALIZING WITH SECRET 0x%016llX\n",
            cfgNode->name, nid, (uintll)cfgNode->secret);

        xtun_node_s* const node = &nodes[nid];

        for (uint pid = 0; pid != PATHS_N; pid++) {

            const xtun_cfg_path_s* const cfgPath = &cfgNode->paths[pid];

            printk("XTUN: TUNNEL %s: PATH %u: INITIALIZING WITH BAND %u PHYS %s TOS 0x%02X TTL %u\n"
                " CLT MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n"
                " SRV MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n",
                cfgNode->name, pid, cfgPath->band, cfgPath->phys, cfgPath->iTOS, cfgPath->iTTL,
                _A6(cfgPath->cltMAC), _A4(cfgPath->cltAddr), cfgPath->cltPort,
                _A6(cfgPath->srvMAC), _A4(cfgPath->srvAddr), PORT(nid, pid)
                );

#if XGW_XTUN_SERVER_IS
            net_device_s* const phys = NULL;
#else
            net_device_s* const phys = dev_get_by_name(&init_net, cfgPath->phys);

            if (!phys) {
                printk("XTUN: TUNNEL %s: CREATE FAILED - PHYS NOT FOUND\n", cfgNode->name);
                continue;
            }

            // THE HOOK OWNS IT
            dev_put(phys);

            if (phys->rx_handler != xtun_in) {
                printk("XTUN: TUNNEL %s: CREATE FAILED - PHYS NOT HOOKED\n", cfgNode->name);
                continue;
            }
#endif
            xtun_path_s* const path = &node->paths[pid];

#if !XGW_XTUN_SERVER_IS
            path->seila      =  0;
            path->bandSrv    =  cfgPath->bandSrv;
#endif
            path->band       =  cfgPath->band;
            path->phys       =  phys;
#if XGW_XTUN_SERVER_IS
            path->hash       =  0; // CLIENT: UNUSED | SERVER: WILL BE DISCOVERED ON INPUT
#endif
#if XGW_XTUN_SERVER_IS
            path->eDst[0]    =  BE16(0);
            path->eDst[1]    =  BE16(0);
            path->eDst[2]    =  BE16(0);
            path->eSrc[0]    =  BE16(0);
            path->eSrc[1]    =  BE16(0);
            path->eSrc[2]    =  BE16(0);
#else
            path->eDst[0]    =  BE16(cfgPath->srvMAC16[0]);
            path->eDst[1]    =  BE16(cfgPath->srvMAC16[1]);
            path->eDst[2]    =  BE16(cfgPath->srvMAC16[2]);
            path->eSrc[0]    =  BE16(cfgPath->cltMAC16[0]);
            path->eSrc[1]    =  BE16(cfgPath->cltMAC16[1]);
            path->eSrc[2]    =  BE16(cfgPath->cltMAC16[2]);
#endif
            path->eType      =  BE16(ETH_P_IP); // FIXED
            path->iVersion   =  BE8(0x45); // FIXED
            path->iTOS       =  BE8(cfgPath->iTOS); // MAY BE ALTERED IN TRANSIT
            path->iSize      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
            path->iHash      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
            path->iFrag      =  BE16(0); // FIXED
            path->iTTL       =  BE8(cfgPath->iTTL); // MAY BE ALTERED IN TRANSIT
            path->iProtocol  =  BE8(IPPROTO_UDP); // FIXED
            path->iCksum     =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
#if XGW_XTUN_SERVER_IS
            path->iSrc       =  BE32(0); // WILL BE DISCOVERED ON INPUT
            path->iDst       =  BE32(0); // WILL BE DISCOVERED ON INPUT
            path->uSrc       =  BE16(PORT(nid, pid));
            path->uDst       =  BE16(0); // WILL BE DISCOVERED ON INPUT
#else
            path->iSrc       =  BE32(cfgPath->cltAddr32);
            path->iDst       =  BE32(cfgPath->srvAddr32);
            path->uSrc       =  BE16(cfgPath->cltPort);
            path->uDst       =  BE16(PORT(nid, pid));
#endif
            path->uSize      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
            path->uCksum     =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
        }

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* const dev = alloc_netdev(sizeof(xtun_node_s*), cfgNode->name, NET_NAME_USER, xtun_dev_setup);

        if (!dev) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT ALLOCATE\n", cfgNode->name);
            continue;
        }

        // INITIALIZE IT, AS WE CAN'T PASS IT TO alloc_netdev()
        *(xtun_node_s**)netdev_priv(dev) = node;

        // MAKE IT VISIBLE IN THE SYSTEM
        if (register_netdev(dev)) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT REGISTER\n", cfgNode->name);
            free_netdev(dev);
            continue;
        }

        // NOW REGISTER IT
        node->dev       = dev;
        node->secret    = cfgNode->secret; // COMMON
        node->key       = 0; // CLIENT: WILL AUTO CHANGE LATER | SERVER: WILL BE DISCOVERED ON INPUT
        node->remaining = 0;
    }

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


//TODO SE O DECODE/AHSH FALHAR, TENTA COM A KEY ANTERIOR
