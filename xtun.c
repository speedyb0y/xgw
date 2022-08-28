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

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

static inline u8  BE8 (u8  x) { return                   x;  }
static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define XTUN_SIZE_ETH (ETH_HDR_SIZE + IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_SIZE_IP  (               IP4_HDR_SIZE + UDP_HDR_SIZE)
#define XTUN_SIZE_UDP (                              UDP_HDR_SIZE)

// EXPECTED SIZE
#define XTUN_SIZE CACHE_LINE_SIZE

typedef struct xtun_s {
    net_device_s* phys;
    u64 hash; // THE PATH HASH
    u32 key;
    u16 id; // TODO: "ENVIA COM DESTINO AO TUNEL Y DO PEER; O PEER SABE QUE SEU TUNEL Y CORRESPONDE AO MEU TUNEL X"
#define ETH_HDR_SIZE 14
    u16 eDst[3];
    u16 eSrc[3];
    u16 eType;
#define IP4_HDR_SIZE 20
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iID; // YOUR TUNNEL ID
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

typedef struct xtun_cfg_s {
    const char virt[IFNAMSIZ];
    const char phys[IFNAMSIZ];
    union { u8 eDst[8]; u16 eDst16[4]; };
    union { u8 eSrc[8]; u16 eSrc16[4]; };
    union { u8 iSrc[4]; u32 iSrc32; };
    union { u8 iDst[4]; u32 iDst32; };
    u8  iTOS;
    u8  iTTL;
    u16 iID;
    u16 uSrc;
    u16 uDst;
    u32 key;
} xtun_cfg_s;

#define XTUN_AUTH_SIZE ((AUTH_REGISTERS_N*2 + AUTH_RANDOMS_N)*sizeof(u64))

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

typedef struct xtun_auth_s {
    u64 registers[AUTH_REGISTERS_N]; // INICIA OS REGISTROS
    u64 verify   [AUTH_REGISTERS_N]; // COMO OS REGISTROS TERMINAM
    u64 randoms  [AUTH_RANDOMS_N];
} xtun_auth_s;

static inline u32 computa (xtun_auth_s* const auth) {

    u64 register0 = AUTH_REGISTER_0 + auth->registers[AUTH_INIT_0];
    u64 register1 = AUTH_REGISTER_1 + auth->registers[AUTH_INIT_1];
    u64 register2 = AUTH_REGISTER_2 + auth->registers[AUTH_INIT_2];
    u64 register3 = AUTH_REGISTER_3 + auth->registers[AUTH_INIT_3];

    for (uint i = 0; i != AUTH_REGISTERS_N; i++) {

        register0 += auth->randoms[register3 % AUTH_RANDOMS_N];
        register1 += auth->randoms[register2 % AUTH_RANDOMS_N];
        register2 += auth->randoms[register1 % AUTH_RANDOMS_N];
        register3 += auth->randoms[register0 % AUTH_RANDOMS_N];

        register0 += register1 >> AUTH_0_ADD_1_SHIFT;
        register2 += register3 >> AUTH_2_ADD_3_SHIFT;
        register1 += AUTH_1_ADD;
        register3 += AUTH_3_ADD;
    }

    const uint ok = (
        register0 == auth->verify[AUTH_VERIFY_0] &&
        register1 == auth->verify[AUTH_VERIFY_1] &&
        register2 == auth->verify[AUTH_VERIFY_2] &&
        register3 == auth->verify[AUTH_VERIFY_3]
    );

    // JUNTA TUDO E TRANSFORMA NA KEY
    register0 += register1;
    register0 += register2;
    register0 += register3;
    register0 += register0 >> 32;
    register0 &= 0xFFFFFFFFULL;
    // SE FOR 0, TRANSFORMA EM 1
    register0 += !register0;
    // RETORNA 0 SE FALHOU, OU UMA KEY SE SUCESSO
    register0 *= ok;

    return register0;
}

#define XTUN_ID(xtun) ((uint)(xtun - virts))

#define SKB_TAIL_PTR(skb) PTR(skb_tail_pointer(skb))

#define TUNS_N (sizeof(cfgs)/sizeof(cfgs[0]))

#define __MAC(a,b,c) a ## b ## c
#define _MAC(x) __MAC(0x,x,U)
#define MAC(a,b,c,d,e,f) { _MAC(a), _MAC(b), _MAC(c), _MAC(d), _MAC(e), _MAC(f) }

static xtun_cfg_s cfgs[] = {
    { .key = 0, .virt = "xgw-0", .iID = 0, .phys = "isp-0", .iTOS = 0, .iTTL = 64,
        .eSrc = MAC(d0,50,99,10,10,10), .iSrc = {192,168,0,20},    .uSrc = 2000,
        .eDst = MAC(54,9F,06,F4,C7,A0), .iDst = {200,200,200,200}, .uDst = 3000,
    },
    { .key = 0, .virt = "xgw-1", .iID = 1, .phys = "isp-1", .iTOS = 0, .iTTL = 64,
        .eSrc = MAC(d0,50,99,11,11,11), .iSrc = {192,168,100,20},  .uSrc = 2111,
        .eDst = MAC(CC,ED,21,96,99,C0), .iDst = {200,200,200,200}, .uDst = 3111,
    },
    { .key = 0, .virt = "xgw-2", .iID = 2, .phys = "isp-2", .iTOS = 0, .iTTL = 64,
        .eSrc = MAC(d0,50,99,12,12,12), .iSrc = {192,168,1,20},    .uSrc = 2222,
        .eDst = MAC(90,55,DE,A1,CD,F0), .iDst = {200,200,200,200}, .uDst = 3222,
    },
};

static net_device_s* virts[TUNS_N];

#define BYTE_X 0x33

static void encode (u64 key, u8* pos, u8* const end) {
    
    while (pos != end) {

        const uint orig = *pos;

        uint value = orig;

        value ^= key;
        value &= 0xFF;
        value |= 0x100;
        value -= BYTE_X;
        value ^= (value & 0xF) << 4;
        value &= 0xFF;

        key <<= 1;
        key += orig;

        *pos++ = value;
    }
}

static void decode (u64 key, u8* pos, u8* const end) {
    
    while (pos != end) {

        uint value = *pos;

        value ^= (value & 0xF) << 4;
        value += BYTE_X;
        value ^= key;
        value &= 0xFF;

        key <<= 1;
        key += value;

        *pos++ = value;
    }
}

static rx_handler_result_t xtun_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    void* const payload = PTR(skb_mac_header(skb)) + XTUN_SIZE_ETH;

    xtun_s* const pkt = PTR(payload) - sizeof(xtun_s);

    // ASSERT: PTR(pkt) >= PTR(skb->head)
    // ASSERT: (PTR(skb_mac_header(skb)) + skb->len) == skb->tail
    // ASSERT: skb->protocol == pkt->eType

    net_device_s* const virt = virts[BE16(pkt->iID) % TUNS_N];

    if (!virt) // NO SUCH TUNNEL
        return RX_HANDLER_PASS;

    xtun_s* const xtun = netdev_priv(virt);

    const u64 hash = (u64)(uintptr_t)skb->dev
      + ((u64)pkt->eDst[0] <<  0)
      + ((u64)pkt->eDst[1] <<  4)
      + ((u64)pkt->eDst[2] <<  8)
      + ((u64)pkt->eSrc[0] << 12)
      + ((u64)pkt->eSrc[1] << 16)
      + ((u64)pkt->eSrc[2] << 20)
      + ((u64)pkt->iSrc    << 24)
      + ((u64)pkt->iDst    << 28)
      + ((u64)pkt->uSrc    << 32)
      + ((u64)pkt->uDst    << 36)
    ;

    // VERIFY PATH
    if (xtun->hash != hash) {
        // THIS IS NOT THE KNOWN PATH

        if (pkt->uDst      != xtun->uSrc // TEM QUE SER NA PORTA EM QUE ESTE TUNEL ESTA ESCUTANDO
         || pkt->iID       != xtun->id
         || pkt->iProtocol != BE8(IPPROTO_UDP)
         || pkt->iVersion  != BE8(0x45)
         || pkt->eType     != BE16(ETH_P_IP)
         || skb->len       != (XTUN_SIZE_ETH + XTUN_AUTH_SIZE)
        ) // IT'S NOT OUR SERVICE / TUN ID MISMATCH / IT'S NOT AUTH
            return RX_HANDLER_PASS;

        const u32 key = computa(payload);

        if (!key) // INCORRECT AUTH / IT'S NOT AUTH
            return RX_HANDLER_PASS;

        printk("XTUN: TUNNEL %s: UPDATING PATH\n", virt->name);

        // COPIA
        xtun->hash    = hash;
        xtun->key     = key;
        xtun->eDst[0] = pkt->eSrc[0];
        xtun->eDst[1] = pkt->eSrc[1];
        xtun->eDst[2] = pkt->eSrc[2];
        xtun->eSrc[0] = pkt->eDst[0];
        xtun->eSrc[1] = pkt->eDst[1];
        xtun->eSrc[2] = pkt->eDst[2];
        xtun->iSrc    = pkt->iDst;
        xtun->iDst    = pkt->iSrc;
        // NOTE: NOSSA PORTA NÃO É ATUALIZADA AQUI:
        //      A PORTA DO SERVIDOR É ESTÁVEL
        //      A PORTA DO CLIENTE É ELE QUE MUDA
        // TANTO QUE NEM VAI CHEGAR ATÉ AQUI SE NÃO FOR PARA A PORTA ATUAL
      //xtun->uSrc    = pkt->uDst;
        xtun->uDst    = pkt->uSrc;

        if (xtun->phys != skb->dev) {
            if (xtun->phys)
                dev_put(xtun->phys);
            dev_hold((xtun->phys = skb->dev));
        }
    }

    decode(xtun->key, payload, SKB_TAIL_PTR(skb));

    // DESENCAPSULA
    skb->mac_len          = 0;
    skb->data             = payload;
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = payload - PTR(skb->head);
    skb->len             -= XTUN_SIZE_ETH;
    skb->dev              = virt;
    skb->protocol         = pkt->eType;

    return RX_HANDLER_ANOTHER;
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

static int __init xtun_init(void) {

    printk("XTUN: INIT\n");

    BUILD_BUG_ON(sizeof(xtun_s) != XTUN_SIZE);
    BUILD_BUG_ON(sizeof(xtun_auth_s) != XTUN_AUTH_SIZE);

    for (uint tid = 0; tid != TUNS_N; tid++) {

        xtun_cfg_s* const cfg = &cfgs[tid];

#define _A6(x) x[0], x[1], x[2], x[3], x[4], x[5]
#define _A4(x) x[0], x[1], x[2], x[3]
        printk("XTUN: TUNNEL %s: INITIALIZING WITH KEY 0x%08X PHYS %s TOS 0x%02X TTL %u"
            " SRC #%u MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u"
            " DST #%u MAC %02X:%02X:%02X:%02X:%02X:%02X IP %u.%u.%u.%u PORT %u"
            "\n",
            cfg->virt, cfg->key,
            cfg->phys, cfg->iTOS, cfg->iTTL,
                 tid, _A6(cfg->eSrc), _A4(cfg->iSrc), cfg->uSrc,
            cfg->iID, _A6(cfg->eDst), _A4(cfg->iDst), cfg->uDst
            );

        net_device_s* const phys = dev_get_by_name(&init_net, cfg->phys);

        if (phys) {

            rtnl_lock();

            if (phys->rx_handler != xtun_in) {
                if (!netdev_rx_handler_register(phys, xtun_in, NULL)) { // TODO: FIXME: TEM QUE FAZER ISSO EM TODAS AS INTERFACES OU NAO VAI PODER CONSIDERAR O SKB COMO xtun_s
                    printk("XTUN: INTERFACE %s: HOOKED\n", phys->name);
                    phys->hard_header_len += sizeof(xtun_s) - ETH_HLEN; // A INTERFACE JA TEM O ETH_HLEN
                    phys->min_header_len  += sizeof(xtun_s) - ETH_HLEN;
                }
            }

            rtnl_unlock();

            if (phys->rx_handler == xtun_in) {

                net_device_s* const virt = alloc_netdev(sizeof(xtun_s), cfg->virt, NET_NAME_USER, xtun_dev_setup);

                if (virt) {

                    if (!register_netdev(virt)) {

                        xtun_s* const xtun = netdev_priv(virt);

                        xtun->phys       =  phys;
                        xtun->hash       =  0;
                        xtun->key        =  cfg->key;
                        xtun->id         =  BE16(tid);
                        xtun->eDst[0]    =  BE16(cfg->eDst16[0]);
                        xtun->eDst[1]    =  BE16(cfg->eDst16[1]);
                        xtun->eDst[2]    =  BE16(cfg->eDst16[2]);
                        xtun->eSrc[0]    =  BE16(cfg->eSrc16[0]);
                        xtun->eSrc[1]    =  BE16(cfg->eSrc16[1]);
                        xtun->eSrc[2]    =  BE16(cfg->eSrc16[2]);
                        xtun->eType      =  BE16(ETH_P_IP);
                        xtun->iVersion   =  BE8(0x45);
                        xtun->iTOS       =  BE8(cfg->iTOS);
                        xtun->iSize      =  BE16(0);
                        xtun->iID        =  BE16(cfg->iID);
                        xtun->iFrag      =  BE16(0);
                        xtun->iTTL       =  BE8(cfg->iTTL);
                        xtun->iProtocol  =  BE8(IPPROTO_UDP);
                        xtun->iCksum     =  BE16(0);
                        xtun->iSrc       =  BE32(cfg->iSrc32);
                        xtun->iDst       =  BE32(cfg->iDst32);
                        xtun->uSrc       =  BE16(cfg->uSrc);
                        xtun->uDst       =  BE16(cfg->uDst);
                        xtun->uSize      =  BE16(0);
                        xtun->uCksum     =  BE16(0);

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
