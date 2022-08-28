/*

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
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <uapi/linux/in6.h>
#include <linux/module.h>

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef signed long long int intll;

typedef struct ethhdr  eth_hdr_s;
typedef struct iphdr   ip4_hdr_s;
typedef struct udphdr  udp_hdr_s;
typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;
typedef struct nlattr nlattr_s;
typedef struct netlink_ext_ack netlink_ext_ack_s;

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

static inline u8  BE8 (u8  x) { return                   x;  }
static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define XTUN_WIRE_SIZE_ETH (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE + XTUN_HDR_SIZE)
#define XTUN_WIRE_SIZE_IP  (               IP4_HDR_SIZE + UDP_HDR_SIZE + XTUN_HDR_SIZE)
#define XTUN_WIRE_SIZE_UDP (                              UDP_HDR_SIZE + XTUN_HDR_SIZE)

// EXPECTED SIZE
#define XTUN_SIZE CACHE_LINE_SIZE

typedef struct xtun_s {
    net_device_s* phys;
#define ETH_HDR_SIZE 14
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
#define IP4_HDR_SIZE 20
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iID;
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iCksum;
    u32 iSrc;
    u32 iDst;
#define UDP_HDR_SIZE 8
    u16 uSrc;
    u16 uDst;
    u16 uSize;
    u16 uCksum;
#define XTUN_HDR_SIZE 10
    u8  xSrc; // SOURCE ID
    u8  xDst; // DESTINATION ID
    u64 xCode;
} xtun_s;

typedef struct xtun_cfg_s {
    const char* virt;
    const char* phys;
    u16  eDst[ETH_ALEN/sizeof(u16)];
    u16  eSrc[ETH_ALEN/sizeof(u16)];
    //u8  iTOS;
    //u16 iID;
    //u8  iTTL;
    u32 iSrc;
    u32 iDst;
    u16 uSrc;
    u16 uDst;
    u8  xSrc; // SOURCE ID
    u8  xDst; // DESTINATION ID
    u64 xCode;
} xtun_cfg_s;

#define XTUN_ID(xtun) ((uint)(xtun - virts))

#define TUNS_N (sizeof(cfgs)/sizeof(cfgs[0]))

#define __MAC(a,b,c,d) a ## b ## c ## d
#define _MAC(a,b) __MAC(0x,a,b,U)
#define MAC(a,b,c,d,e,f) { _MAC(a,b), _MAC(c,d), _MAC(e,f) }

#define IP4(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define XTUN_CFG(v, p, seth, sip, sudp, deth, dip, dudp) { \
    .virt = v, \
    .phys = p, \
    .eSrc = seth, \
    .eDst = deth, \
    .iSrc = sip, \
    .iDst = dip, \
    .uSrc = sudp, \
    .uDst = dudp, \
    }

static xtun_cfg_s cfgs[] = {
    XTUN_CFG("xgw-0", "isp-0",
        MAC(d0,50,99,10,10,10), IP4(192,168,0,20),    2000,
        MAC(54,9F,06,F4,C7,A0), IP4(200,200,200,200), 3000
    ),
    XTUN_CFG("xgw-1", "isp-1",
        MAC(d0,50,99,11,11,11), IP4(192,168,100,20),  2111,
        MAC(CC,ED,21,96,99,C0), IP4(200,200,200,200), 3111
    ),
    XTUN_CFG("xgw-2", "isp-2",
        MAC(d0,50,99,12,12,12), IP4(192,168,1,20),    2222,
        MAC(90,55,DE,A1,CD,F0), IP4(200,200,200,200), 3222
    ),
};

static net_device_s* virts[TUNS_N];

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    xtun_s* const pkt = PTR(skb_mac_header(skb));

    const uint tid = BE8(pkt->xDst);

    if (tid < TUNS_N) {

        net_device_s* const virt = virts[tid];

        xtun_s* const xtun = netdev_priv(virt);

        if (xtun->xCode == pkt->xCode
         && xtun->xSrc  == pkt->xDst
         && xtun->xDst  == pkt->xSrc
        ) { // IT'S AUTHENTIC

            // UPDATE PATH
            if (unlikely(
                xtun->eDst[0] != pkt->eSrc[0]
             || xtun->eDst[1] != pkt->eSrc[1]
             || xtun->eDst[2] != pkt->eSrc[2]
             || xtun->eSrc[0] != pkt->eDst[0]
             || xtun->eSrc[1] != pkt->eDst[1]
             || xtun->eSrc[2] != pkt->eDst[2]
             || xtun->iSrc    != pkt->iDst
             || xtun->iDst    != pkt->iSrc
             || xtun->uSrc    != pkt->uDst
             || xtun->uDst    != pkt->uSrc
             || xtun->phys    != skb->dev
            )) {

                printk("XTUN: TUNNEL %s: UPDATING PATH\n", virt->name);

                //
                xtun->eDst[0] = pkt->eSrc[0];
                xtun->eDst[1] = pkt->eSrc[1];
                xtun->eDst[2] = pkt->eSrc[2];
                xtun->eSrc[0] = pkt->eDst[0];
                xtun->eSrc[1] = pkt->eDst[1];
                xtun->eSrc[2] = pkt->eDst[2];
                xtun->iSrc    = pkt->iDst;
                xtun->iDst    = pkt->iSrc;
                xtun->uSrc    = pkt->uDst;
                xtun->uDst    = pkt->uSrc;

                if (xtun->phys != skb->dev) {
                    if (xtun->phys)
                        dev_put(xtun->phys);
                    dev_hold((xtun->phys = skb->dev));
                }
            }

            // DESENCAPSULA
            skb->mac_len          = 0;
            skb->data             = PTR(pkt) + XTUN_WIRE_SIZE_ETH;
            skb->mac_header       =
            skb->network_header   =
            skb->transport_header =
                skb->data - skb->head;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
            skb->len = skb->head + skb->tail - skb->data;
#else
            skb->len = skb->tail - skb->data;
#endif
            skb->dev = virt;
            skb->protocol = pkt->eType;

            return RX_HANDLER_ANOTHER;
        }
    }

    return RX_HANDLER_PASS;
}

static netdev_tx_t xtun_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    // ASSERT: skb->len <= xtun->mtu
    // ASSERT: skb->len <= xtun->virt->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER
    // ASSERT: skb->len <= xtun->phys->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER

    // ENCAPSULATE
    xtun_s* const pkt = PTR(skb->data) - sizeof(xtun_s);

    // ASSERT: PTR(skb_mac_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(skb_network_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(pkt) >= PTR(skb->head)

    memcpy(pkt, netdev_priv(dev), sizeof(xtun_s));

    pkt->uSize  = BE16(skb->len + XTUN_WIRE_SIZE_UDP);
    pkt->iSize  = BE16(skb->len + XTUN_WIRE_SIZE_IP);
    pkt->iCksum = ip_fast_csum((void*)pkt, 5);

    skb->transport_header = PTR(&pkt->uSrc)     - PTR(skb->head);
    skb->network_header   = PTR(&pkt->iVersion) - PTR(skb->head);
    skb->mac_header       = PTR(pkt)            - PTR(skb->head);
    skb->data             = PTR(pkt);
    skb->len             += XTUN_WIRE_SIZE_ETH;
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
    dev->hard_header_len = XTUN_WIRE_SIZE_ETH; // ETH_HLEN
    dev->min_header_len  = XTUN_WIRE_SIZE_ETH;
    dev->mtu             = 1500 - 28 - XTUN_WIRE_SIZE_ETH; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - XTUN_WIRE_SIZE_ETH; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - XTUN_WIRE_SIZE_ETH; // ETH_MAX_MTU
    dev->addr_len        = 0;
    dev->tx_queue_len    = 0; // EFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
                        // IFF_NO_RX_HANDLER?
        ;
}

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_s) != XTUN_SIZE);

    for (uint tid = 0; tid != TUNS_N; tid++) {

        xtun_cfg_s* const cfg = &cfgs[tid];

        printk("XTUN: TUNNEL %s: INITIALIZING WITH PHYS %s CODE 0x%16llX"
            " SRC #%u MAC %02X%02X%02X IP 0x%08X PORT %u"
            " DST #%u MAC %02X%02X%02X IP 0x%08X PORT %u"
            "\n",
            cfg->virt,
            cfg->phys,
            cfg->xCode,
            cfg->xSrc, cfg->eSrc[0], cfg->eSrc[1], cfg->eSrc[2], cfg->iSrc, cfg->uSrc,
            cfg->xDst, cfg->eDst[0], cfg->eDst[1], cfg->eDst[2], cfg->iDst, cfg->uDst
            );

        net_device_s* const phys = dev_get_by_name(&init_net, cfg->phys);

        if (phys) {

            if (phys->rx_handler != xtun_in) {
                if (!netdev_rx_handler_register(phys, xtun_in, NULL)) {
                    printk("XTUN: INTERFACE %s: HOOKED\n", phys->name);
                    phys->hard_header_len += sizeof(xtun_s) - ETH_HLEN; // A INTERFACE JA TEM O ETH_HLEN
                    phys->min_header_len  += sizeof(xtun_s) - ETH_HLEN;
                }
            }

            if (phys->rx_handler == xtun_in) {

                net_device_s* const virt = alloc_netdev(sizeof(xtun_s), cfg->virt, NET_NAME_USER, xtun_dev_setup);

                if (virt) {

                    if (!register_netdev(virt)) {

                        xtun_s* const xtun = netdev_priv(virt);

                        xtun->phys       =  phys;
                        xtun->eDst[0]    =  BE16(cfg->eDst[0]);
                        xtun->eDst[1]    =  BE16(cfg->eDst[1]);
                        xtun->eDst[2]    =  BE16(cfg->eDst[2]);
                        xtun->eSrc[0]    =  BE16(cfg->eSrc[0]);
                        xtun->eSrc[1]    =  BE16(cfg->eSrc[1]);
                        xtun->eSrc[2]    =  BE16(cfg->eSrc[2]);
                        xtun->eType      =  BE16(ETH_P_IP);
                        xtun->iVersion   =  BE8(0x45);
                        xtun->iTOS       =  BE8(0);
                        xtun->iSize      =  BE16(0);
                        xtun->iID        =  BE16(0x2562);
                        xtun->iFrag      =  BE16(0);
                        xtun->iTTL       =  BE8(64);
                        xtun->iProtocol  =  BE16(IPPROTO_UDP);
                        xtun->iCksum     =  BE16(0);
                        xtun->iSrc       =  BE32(cfg->iSrc);
                        xtun->iDst       =  BE32(cfg->iDst);
                        xtun->uSrc       =  BE16(cfg->uSrc);
                        xtun->uDst       =  BE16(cfg->uDst);
                        xtun->uSize      =  BE16(0);
                        xtun->uCksum     =  BE16(0);
                        xtun->xSrc       =  BE8(cfg->xSrc);
                        xtun->xDst       =  BE8(cfg->xDst);
                        xtun->xCode      =  BE64(cfg->xCode);

                        virts[tid] = virt;

                        continue;
                    }

                    printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT REGISTER\n", cfg->virt);

                    free_netdev(virt);

                } else
                    printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT ALLOCATE\n", cfg->virt);
            } else
                printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT HOOK PHYS\n", cfg->virt);

            dev_put(phys);

        } else
            printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT FIND PHYS\n", cfg->virt);

        virts[tid] = NULL;
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
