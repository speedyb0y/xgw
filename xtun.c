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

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define SKB_TAIL_PTR(skb) PTR(skb_tail_pointer(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

static inline u8  BE8 (u8  x) { return                   x;  }
static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define XTUN_SERVER_PORT XGW_XTUN_SERVER_PORT

// EXPECTED SIZE
#define XTUN_SIZE CACHE_LINE_SIZE

#define XTUN_SIZE_ALL (XTUN_SIZE_PRIVATE + XTUN_SIZE_ETH)
#define XTUN_SIZE_PRIVATE   (sizeof(net_device_s*) + sizeof(u64) + sizeof(u32) + sizeof(u16))
#define XTUN_SIZE_ETH       (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_SIZE_IP        (               IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_SIZE_UDP       (                              UDP_HDR_SIZE)

typedef struct xtun_s {
    net_device_s* phys;
#if XGW_XTUN_SERVER_IS
    u64 hash; // THE PATH HASH
#else
    u64 reserved;
#endif
    u32 key; // DINAMICO, GERADO PELO CLIENTE
    u16 secret; // COMUM ENTRE AMBAS AS PARTES, NUNCA REPASSADO
#define ETH_HDR_SIZE 14
    u16 eDst[3];
    u16 eSrc[3];
    u16 eType;
#define IP4_HDR_SIZE 20
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iHash;
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
} xtun_s;

#define __MAC(a,b,c) a ## b ## c
#define _MAC(x) __MAC(0x,x,U)
#define MAC(a,b,c,d,e,f) { _MAC(a), _MAC(b), _MAC(c), _MAC(d), _MAC(e), _MAC(f) }

typedef struct xtun_cfg_s {
    u16 id;
    u16 secret;
    const char virt[IFNAMSIZ];
    const char phys[IFNAMSIZ];
    union { u8 cltMAC[8]; u16 cltMAC16[4]; };
    union { u8 srvMAC[8]; u16 srvMAC16[4]; };
    union { u8 cltAddr[4]; u32 cltAddr32; };
    union { u8 srvAddr[4]; u32 srvAddr32; };
    u16 cltPort;
    u8  iTOS;
    u8  iTTL;
} xtun_cfg_s;

#define TUNS_N 4096

static net_device_s* virts[TUNS_N];

static const xtun_cfg_s cfgs[] = {
    {.id = 0, .secret = 0, .virt = "xgw-0", .phys = "isp-0", .iTOS = 0, .iTTL = 64,
        .cltMAC = MAC(d0,50,99,10,10,10), .cltAddr = {192,168,0,20},    .cltPort = 2000,
        .srvMAC = MAC(54,9F,06,F4,C7,A0), .srvAddr = {200,200,200,200}
    },
    { .id = 1, .secret = 0, .virt = "xgw-1", .phys = "isp-1", .iTOS = 0, .iTTL = 64,
        .cltMAC = MAC(d0,50,99,11,11,11), .cltAddr = {192,168,100,20},  .cltPort = 2111,
        .srvMAC = MAC(CC,ED,21,96,99,C0), .srvAddr = {200,200,200,200}
    },
    { .id = 2, .secret = 0, .virt = "xgw-2", .phys = "isp-2", .iTOS = 0, .iTTL = 64,
        .cltMAC = MAC(d0,50,99,12,12,12), .cltAddr = {192,168,1,20},    .cltPort = 2222,
        .srvMAC = MAC(90,55,DE,A1,CD,F0), .srvAddr = {200,200,200,200}
    },
};

#define AUTH_LOOP_COUNT 8
// NAO PODE SER NEM O PRIMEIRO, E NEM O ULTIMO
#define AUTH_LOOP_VERIFY 3

#define AUTH_REGISTERS_N 4
#define AUTH_RANDOMS_N 128

#define AUTH_REGISTER_0 0x0000000000000000ULL
#define AUTH_REGISTER_1 0x0000000000000000ULL
#define AUTH_REGISTER_2 0x0000000000000000ULL
#define AUTH_REGISTER_3 0x0000000000000000ULL

#define AUTH_0_ADD_1_SHIFT 4
#define AUTH_2_ADD_3_SHIFT 3
#define AUTH_1_ADD 0x34234340ULL
#define AUTH_3_ADD 0x32432432ULL

#define AUTH_INIT_0 0
#define AUTH_INIT_1 3
#define AUTH_INIT_2 1
#define AUTH_INIT_3 2

#define AUTH_VERIFY_0 0
#define AUTH_VERIFY_1 3
#define AUTH_VERIFY_2 1
#define AUTH_VERIFY_3 2

#define XTUN_AUTH_SIZE ((AUTH_REGISTERS_N + AUTH_RANDOMS_N)*sizeof(u64))

typedef struct xtun_auth_s {
    u64 verify   [AUTH_REGISTERS_N]; // COMO OS REGISTROS TERMINAM
    u64 randoms  [AUTH_RANDOMS_N];
} xtun_auth_s;

static u32 xtun_auth_key_ (const u16 secret, xtun_auth_s* const auth, bool save) {

    u64 register0 = AUTH_REGISTER_0 + secret + auth->randoms[AUTH_INIT_0];
    u64 register1 = AUTH_REGISTER_1 + secret + auth->randoms[AUTH_INIT_1];
    u64 register2 = AUTH_REGISTER_2 + secret + auth->randoms[AUTH_INIT_2];
    u64 register3 = AUTH_REGISTER_3 + secret + auth->randoms[AUTH_INIT_3];

    for (uint c = AUTH_LOOP_COUNT; c; c--) {

        register0 += auth->randoms[register3 & (AUTH_RANDOMS_N - 1)];
        register1 += auth->randoms[register2 & (AUTH_RANDOMS_N - 1)];
        register2 += auth->randoms[register1 & (AUTH_RANDOMS_N - 1)];
        register3 += auth->randoms[register0 & (AUTH_RANDOMS_N - 1)];

        register0 += auth->randoms[register1 & (AUTH_RANDOMS_N - 1)];
        register1 += auth->randoms[register2 & (AUTH_RANDOMS_N - 1)];
        register2 += auth->randoms[register3 & (AUTH_RANDOMS_N - 1)];
        register3 += auth->randoms[register0 & (AUTH_RANDOMS_N - 1)];

        if (c == AUTH_LOOP_VERIFY) {
            if (save) {
                auth->verify[AUTH_VERIFY_0] = register0;
                auth->verify[AUTH_VERIFY_1] = register1;
                auth->verify[AUTH_VERIFY_2] = register2;
                auth->verify[AUTH_VERIFY_3] = register3;
            } else
                save =
                    register0 == auth->verify[AUTH_VERIFY_0] &&
                    register1 == auth->verify[AUTH_VERIFY_1] &&
                    register2 == auth->verify[AUTH_VERIFY_2] &&
                    register3 == auth->verify[AUTH_VERIFY_3];
        }

        register0 += register1 >> AUTH_0_ADD_1_SHIFT;
        register2 += register3 >> AUTH_2_ADD_3_SHIFT;
        register1 += AUTH_1_ADD;
        register3 += AUTH_3_ADD;
    }

    // JUNTA TUDO E TRANSFORMA NA KEY
    register0 += register1;
    register0 += register2;
    register0 += register3;
    register0 += register0 >> 32;
    register0 &= 0xFFFFFFFFULL;
    // SE FOR 0, TRANSFORMA EM 1
    register0 += !register0;
    // RETORNA 0 SE FALHOU, OU UMA KEY SE SUCESSO
    register0 *= save;

    return (u32)register0;
}

static inline u32 xtun_auth_key_gen (const u16 secret, xtun_auth_s* const auth) {

    return xtun_auth_key_(secret, auth, true);
}

static inline u32 xtun_auth_key_check (const u16 secret, xtun_auth_s* const auth) {

    return xtun_auth_key_(secret, auth, false);
}

#include "xtun-encoding.c"

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    const xtun_s* const hdr = PTR(skb_mac_header(skb)) - XTUN_SIZE_PRIVATE;

    void* const payload = PTR(hdr) + sizeof(*hdr);

    //XTUN_ASSERT(skb->dev != virt);
    XTUN_ASSERT(PTR(hdr->eDst) >= PTR(skb->head));
    // ASSERT: (PTR(skb_mac_header(skb)) + skb->len) == skb->tail
    // ASSERT: skb->protocol == hdr->eType

    if (skb->len < XTUN_SIZE_ETH
     || hdr->eType     != BE16(ETH_P_IP)
     || hdr->iVersion  != BE8(0x45)
     || hdr->iProtocol != BE8(IPPROTO_UDP))
        // NOT UDP/IPV4/ETHERNET
        goto pass;

    // WILL UNSIGNED OVERFLOW IF LOWER
#if XGW_XTUN_SERVER_IS
    const uint id = BE16(hdr->uDst) - XTUN_SERVER_PORT;
#else
    const uint id = BE16(hdr->uSrc) - XTUN_SERVER_PORT;
#endif

    if (id >= TUNS_N)
        // NOT IN SERVER PORT RANGE
        goto pass;

    net_device_s* const virt = virts[id];

    if (!virt)
        // NO SUCH TUNNEL
        goto pass;

    // ASSERT: hdr->uDst == xtun->uSrc

    xtun_s* const xtun = netdev_priv(virt);

#define XTUN_HASH_PREPARE hash64_16_01

    if (hdr->iHash) {
        // NOT AUTH
        if (XTUN_HASH_PREPARE(xtun_decode(xtun->secret, xtun->key, payload, SKB_TAIL_PTR(skb))) != hdr->iHash)
            // HASH MISMATCH
            goto drop;
    } else {
        // AUTH
#if XGW_XTUN_SERVER_IS
        if (skb->len != (XTUN_SIZE_ETH + XTUN_AUTH_SIZE))
            // INVALID AUTH SIZE
            goto drop;
        if (!(key = xtun_auth_key_check(xtun->secret, payload)))
            // INCORRECT AUTH
            goto drop;
        // USA ELA
        xtun->key = key;
#else // UNEXPECTED AUTH FROM SERVER
        goto drop;
#endif
    }

#if XGW_XTUN_SERVER_IS
    // DETECT AND UPDATE PATH CHANGES

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

    if (xtun->hash != hash) {

        printk("XTUN: TUNNEL %s: UPDATING PATH\n", virt->name);

        if (xtun->phys != dev) {
            if (xtun->phys)
                dev_put(xtun->phys);
            dev_hold(dev);
        }

        xtun->hash    = hash;
        xtun->phys    = dev;
        xtun->eDst[0] = hdr->eSrc[0];
        xtun->eDst[1] = hdr->eSrc[1];
        xtun->eDst[2] = hdr->eSrc[2];
        xtun->eSrc[0] = hdr->eDst[0];
        xtun->eSrc[1] = hdr->eDst[1];
        xtun->eSrc[2] = hdr->eDst[2];
        xtun->iSrc    = hdr->iDst;
        xtun->iDst    = hdr->iSrc;
        // NOTE: NOSSA PORTA NÃO É ATUALIZADA AQUI:
        //      A PORTA DO SERVIDOR É ESTÁVEL
        //      A PORTA DO CLIENTE É ELE QUE MUDA
        // TANTO QUE NEM VAI CHEGAR ATÉ AQUI SE NÃO FOR PARA A PORTA ATUAL
      //xtun->uSrc    = hdr->uDst;
        xtun->uDst    = hdr->uSrc;
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
    skb->len             -= XTUN_SIZE_ETH;
    skb->dev              = virt;
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
    xtun_s* const pkt = PTR(skb->data) - sizeof(xtun_s);

    // ASSERT: PTR(skb_mac_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(skb_network_header(skb)) == PTR(skb->data)
    // ASSERT: PTR(pkt) >= PTR(skb->head)

    memcpy(pkt, netdev_priv(dev), sizeof(xtun_s));

    pkt->uSize  = BE16(skb->len + XTUN_SIZE_UDP);
    pkt->iSize  = BE16(skb->len + XTUN_SIZE_IP);
    pkt->iCksum = ip_fast_csum((void*)pkt, 5);

    skb->transport_header = PTR(&pkt->uSrc)     - PTR(skb->head);
    skb->network_header   = PTR(&pkt->iVersion) - PTR(skb->head);
    skb->mac_header       = PTR(&pkt->eDst)     - PTR(skb->head);
    skb->data             = PTR(&pkt->eDst);
    skb->len             += XTUN_SIZE_ETH;
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
    dev->hard_header_len = XTUN_SIZE_ETH; // ETH_HLEN
    dev->min_header_len  = XTUN_SIZE_ETH;
    dev->mtu             = 1500 - 28 - XTUN_SIZE_ETH; // ETH_DATA_LEN
    dev->min_mtu         = 1500 - 28 - XTUN_SIZE_ETH; // ETH_MIN_MTU
    dev->max_mtu         = 1500 - 28 - XTUN_SIZE_ETH; // ETH_MAX_MTU
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

static void xtun_dev_initialize (xtun_s* const xtun, const xtun_cfg_s* const cfg, net_device_s* const phys) {

    xtun->phys       =  phys;
#if XGW_XTUN_SERVER_IS
    xtun->hash       =  0; // CLIENT: UNUSED | SERVER: WILL BE DISCOVERED ON INPUT
#endif
    xtun->secret     =  cfg->secret; // COMMON
    xtun->key        =  0; // CLIENT: WILL AUTO CHANGE LATER | SERVER: WILL BE DISCOVERED ON INPUT
#if XGW_XTUN_SERVER_IS
    xtun->eDst[0]    =  BE16(0);
    xtun->eDst[1]    =  BE16(0);
    xtun->eDst[2]    =  BE16(0);
    xtun->eSrc[0]    =  BE16(0);
    xtun->eSrc[1]    =  BE16(0);
    xtun->eSrc[2]    =  BE16(0);
#else
    xtun->eDst[0]    =  BE16(cfg->srvMAC16[0]);
    xtun->eDst[1]    =  BE16(cfg->srvMAC16[1]);
    xtun->eDst[2]    =  BE16(cfg->srvMAC16[2]);
    xtun->eSrc[0]    =  BE16(cfg->cltMAC16[0]);
    xtun->eSrc[1]    =  BE16(cfg->cltMAC16[1]);
    xtun->eSrc[2]    =  BE16(cfg->cltMAC16[2]);
#endif
    xtun->eType      =  BE16(ETH_P_IP); // FIXED
    xtun->iVersion   =  BE8(0x45); // FIXED
    xtun->iTOS       =  BE8(cfg->iTOS); // MAY BE ALTERED IN TRANSIT
    xtun->iSize      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
    xtun->iHash      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
    xtun->iFrag      =  BE16(0); // FIXED
    xtun->iTTL       =  BE8(cfg->iTTL); // MAY BE ALTERED IN TRANSIT
    xtun->iProtocol  =  BE8(IPPROTO_UDP); // FIXED
    xtun->iCksum     =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
#if XGW_XTUN_SERVER_IS
    xtun->iSrc       =  BE32(0); // WILL BE DISCOVERED ON INPUT
    xtun->iDst       =  BE32(0); // WILL BE DISCOVERED ON INPUT
    xtun->uSrc       =  BE16(XTUN_SERVER_PORT + cfg->id);
    xtun->uDst       =  BE16(0); // WILL BE DISCOVERED ON INPUT
#else
    xtun->iSrc       =  BE32(cfg->cltAddr32);
    xtun->iDst       =  BE32(cfg->srvAddr32);
    xtun->uSrc       =  BE16(cfg->cltPort);
    xtun->uDst       =  BE16(XTUN_SERVER_PORT + cfg->id);
#endif
    xtun->uSize      =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
    xtun->uCksum     =  BE16(0); // WILL BE COMPUTED ON ENCAPSULATION
}

#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))

static const char* const itfcs[] = { "eth0" };

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_s) != XTUN_SIZE);
    BUILD_BUG_ON(sizeof(xtun_s) != XTUN_SIZE_ALL);
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
                // TODO: FIXME: TEM QUE FAZER ISSO EM TODAS AS INTERFACES OU NAO VAI PODER CONSIDERAR O SKB COMO xtun_s
                printk("XTUN: INTERFACE %s: HOOKED\n", itfc);
                dev->hard_header_len += sizeof(xtun_s) - ETH_HLEN; // A INTERFACE JA TEM O ETH_HLEN
                dev->min_header_len  += sizeof(xtun_s) - ETH_HLEN;
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
    memset(virts, 0, sizeof(virts));

    for (uint i = 0; i != ARRAY_COUNT(cfgs); i++) {

        const xtun_cfg_s* const cfg = &cfgs[i];

        printk("XTUN: TUNNEL %s: INITIALIZING WITH ID #%u SECRET 0x%04X PHYS %s TOS 0x%02X TTL %u\n"
            " CLT MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n"
            " SRV MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u\n",
            cfg->virt, cfg->id, cfg->secret, cfg->phys, cfg->iTOS, cfg->iTTL,
            _A6(cfg->cltMAC), _A4(cfg->cltAddr), cfg->cltPort,
            _A6(cfg->srvMAC), _A4(cfg->srvAddr), XTUN_SERVER_PORT
            );

#if XGW_XTUN_SERVER_IS
        net_device_s* const phys = NULL;
#else
        net_device_s* const phys = dev_get_by_name(&init_net, cfg->phys);

        if (!phys) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - PHYS NOT FOUND\n", cfg->virt);
            continue;
        }

        // THE HOOK OWNS IT
        dev_put(phys);

        if (phys->rx_handler != xtun_in) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - PHYS NOT HOOKED\n", cfg->virt);
            continue;
        }
#endif

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* const virt = alloc_netdev(sizeof(xtun_s), cfg->virt, NET_NAME_USER, xtun_dev_setup);

        if (!virt) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT ALLOCATE\n", cfg->virt);
            continue;
        }

        // INITIALIZE IT, AS WE CAN'T PASS THE CONFIG TO alloc_netdev()
        xtun_dev_initialize((xtun_s*)netdev_priv(virt), cfg, phys);

        // MAKE IT VISIBLE IN THE SYSTEM
        if (register_netdev(virt)) {
            printk("XTUN: TUNNEL %s: CREATE FAILED - COULD NOT REGISTER\n", cfg->virt);
            free_netdev(virt);
            continue;
        }

        // NOW REGISTER IT
        virts[cfg->id] = virt;
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


TODO SE O DECODE/AHSH FALHAR, TENTA COM A KEY ANTERIOR
