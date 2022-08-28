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

#ifdef NET_SKBUFF_DATA_USES_OFFSET
#define SKB_LEN(skb) ((skb)->head + (skb)->tail - (skb)->data)
#else
#define SKB_LEN(skb) ((skb)->tail - (skb)->data)
#endif

#define CACHE_LINE_SIZE 64

#define XTUN_ALIGNED_SIZE CACHE_LINE_SIZE

#define XTUN_WIRE_SIZE (ETH_HLEN + 20 + 8 + 10)

typedef struct xtun_hdr_s {
    union { net_device_s* virt; const char* virtName; };
    union { net_device_s* phys; const char* physName; };
    // ETHERNET
    u8  eDst[ETH_ALEN];
    u8  eSrc[ETH_ALEN];
    u16 eType;
    // IP
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
    // UDP
    u16 uSrc;
    u16 uDst;
    u16 uSize;
    u16 uCksum;
    // XTUN
    u8  xSrcID; // SOURCE ID
    u8  xDstID; // DESTINATION ID
    u32 xSrcCode;
    u32 xDstCode;
} xtun_hdr_s;

#define XTUN_ID(xtun) ((uint)(xtun - xtuns))

#define TUNS_N (sizeof(xtuns)/sizeof(xtuns[0]))

#define __HEX(a,b,c) a ## b ## c
#define _HEX(x) __HEX(0x,x,U)

#define MAC(a,b,c,d,e,f) { _HEX(a), _HEX(b), _HEX(c), _HEX(d), _HEX(e), _HEX(f) }
#define IP4(a,b,c,d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define XTUN_CFG(v, p, mmac, mip, mport, pmac, pip, pport) { \
    .virtName = v, \
    .physName = p, \
    .i = { \
        .eSrc = pmac, \
        .eDst = mmac, \
        .iSrc = pip, \
        .iDst = mip, \
        .uSrc = pport, \
        .uDst = mport, \
    }}

static xtun_s xtuns[] = {
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

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    xtun_hdr_s* const pkt = PTR(skb_mac_header(skb));

    const uint tid = BE8(pkt->xDstID);

    if (tid > TUNS_N) {

        xtun_s* const xtun = &xtuns[tid];

        if (xtun->xSrcCode == pkt->xDstCode &&
            xtun->keyB == pkt->keyB) {

            if (xtun->me[0] == pkt->eDst[0] &&
                xtun->me[1] == pkt->eDst[1] &&
                xtun->me[2] == pkt->eDst[2] &&
                xtun->gw[0] == pkt->eSrc[0] &&
                xtun->gw[1] == pkt->eSrc[1] &&
                xtun->gw[2] == pkt->eSrc[2] &&
                xtun->phys == skb->dev &&
                xtun->virt) {
                // DESENCAPSULA
                skb->mac_len          = 0;
                skb->data             = PTR(pkt) + XTUN_WIRE_SIZE;
                skb->mac_header       =
                skb->network_header   =
                skb->transport_header =
                    skb->data - skb->head;
                skb->len = SKB_LEN(skb);
                skb->dev = xtun->virt;
                skb->protocol = pkt->eType;

                return RX_HANDLER_ANOTHER;
            }
        }
    }

    return RX_HANDLER_PASS;
}

static netdev_tx_t xtun_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    // ASSERT: skb->len <= xtun->mtu
    // ASSERT: skb->len <= xtun->virt->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER
    // ASSERT: skb->len <= xtun->phys->mtu  -> MAS DEIXANDO A CARGO DO RESPECTIVO NETWORK STACK/DRIVER

    xtun_s* const xtun = *(xtun_s**)netdev_priv(dev);

    if (xtun->phys) {

        xtun_hdr_s* const pkt = PTR(skb_mac_header(skb)) - ETH_HLEN;

        BUG_ON(PTR(pkt) < PTR(skb->head));

        // ENCAPSULATE
        copy(pkt, path, XTUN_HDR_SIZE);

        pkt->uSize  = BE16(0);
        pkt->iSize  = BE16(0);
        pkt->iCksum = BE16(0);

        skb->mac_len         = ETH_HLEN;
        skb->mac_header      = PTR(pkt) - PTR(skb->head);
        skb->data            = PTR(pkt);
        skb->len             = SKB_LEN(skb);
        skb->protocol        = BE16(ETH_P_IP);
        skb->ip_summed       = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
        skb->dev             = xtun->phys;

        // THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
        // WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
        dev_queue_xmit(skb);
    } else
        dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xtun_dev_up (net_device_s* const dev) {

    xtun_s* const xtun = *(xtun_s**)netdev_priv(dev);

    printk("XTUN: VID %u UP\n", XTUN_ID(xtun));

    return 0;
}

static int xtun_dev_down (net_device_s* const dev) {

    xtun_s* const xtun = *(xtun_s**)netdev_priv(dev);

    printk("XTUN: VID %u DOWN\n", XTUN_ID(xtun));

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
    dev->hard_header_len = ETH_HLEN + 20 + 8;
    dev->min_header_len  = ETH_HLEN + 20 + 8;
    dev->mtu             = 1500 - 28 - 20 - 8; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - 20 - 8; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - 20 - 8; // ETH_MAX_MTU
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

    BUILD_BUG_ON(sizeof(xtun_s) != XTUN_ALIGNED_SIZE);

    for (uint tid = 0; tid != TUNS_N; tid++) {

        xtun_s* const xtun = &xtuns[tid];

        printk("XTUN: VID %u - INITIALIZING WITH VIRT %s PHYS %s\n", tid,
            xtun->virtName,
            xtun->physName
            );

        net_device_s* const phys = dev_get_by_name(xtun->physName);

        if (phys) {

            if (phys->rx_handler != xtun_in) {
                if (!netdev_rx_handler_register(phys, xtun_in, NULL)) {
                    dev->hard_header_len += 20 + 8;
                    dev->min_header_len  += 20 + 8;
                }
            }

            if (phys->rx_handler == xtun_in) {

                net_device_s* const virt = alloc_netdev(sizeof(xtun_s**), xtun->virtName, NET_NAME_USER, xtun_dev_setup);

                if (virt) {

                    if (!register_netdev(virt)) {

                        *(xtun_s**)netdev_priv(virt) = xtun;

                        xtun->virt       =  virt;
                        xtun->phys       =  phys;
                        xtun->eType      =  BE16(ETH_P_IP);
                        xtun->iVersion   =  BE8(0x45);
                        xtun->iTOS       =  BE8(0);
                        xtun->iSize      =  BE16(0);
                        xtun->iID        =  BE16(0x2562);
                        xtun->iFrag      =  BE16(0);
                        xtun->iTTL       =  BE8(64);
                        xtun->iProtocol  =  IPPROTO_UDP;
                        xtun->iCksum     =  0;
                        xtun->iSrc       =  BE32(xtun->iSrc);
                        xtun->iDst       =  BE32(xtun->iDst);
                        xtun->uSrc       =  BE16(xtun->uSrc);
                        xtun->uDst       =  BE16(xtun->uDst);
                        xtun->uSize      =  0;
                        xtun->uCksum     =  0;
                        xtun->xSrcID     =  BE8(xtun->xSrcID);
                        xtun->xDstID     =  BE8(xtun->xDstID);
                        xtun->xSrcCode   =  BE64(xtun->xSrcCode);
                        xtun->xDstCode   =  BE64(xtun->xDstCode);

                        continue;
                    }

                    free_netdev(virt);
                }
            }

            dev_put(phys);
        }

        printk("XTUN: VID %u - FAILED TO CREATE\n", tid);

        xtun->virt = NULL;
        xtun->phys = NULL;
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
