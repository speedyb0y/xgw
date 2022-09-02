
#define XTUN_KEYS_N XGW_XTUN_KEYS_N

#define XTUN_CRYPTO_SHIFT32_KEY_0_ADD XGW_XTUN_CRYPTO_SHIFT32_KEY_0_ADD
#define XTUN_CRYPTO_SHIFT32_KEY_1_ADD XGW_XTUN_CRYPTO_SHIFT32_KEY_1_ADD
#define XTUN_CRYPTO_SHIFT32_KEY_2_ADD XGW_XTUN_CRYPTO_SHIFT32_KEY_2_ADD
#define XTUN_CRYPTO_SHIFT32_KEY_3_ADD XGW_XTUN_CRYPTO_SHIFT32_KEY_3_ADD

#define XTUN_CRYPTO_SHIFT64_KEY_0_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_0_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_1_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_1_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_2_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_2_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_3_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_3_ADD

#if XTUN_CRYPTO_SHIFT32_KEY_0_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT32_KEY_0_ADD > 0xFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT32_KEY_0_ADD"
#endif

#if XTUN_CRYPTO_SHIFT32_KEY_1_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT32_KEY_1_ADD > 0xFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT32_KEY_1_ADD"
#endif

#if XTUN_CRYPTO_SHIFT32_KEY_2_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT32_KEY_2_ADD > 0xFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT32_KEY_2_ADD"
#endif

#if XTUN_CRYPTO_SHIFT32_KEY_3_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT32_KEY_3_ADD > 0xFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT32_KEY_3_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_0_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_0_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_0_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_1_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_1_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_1_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_2_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_2_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_2_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_3_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_3_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_3_ADD"
#endif

#define popcount32(x) __builtin_popcount((uint)(x))
#define popcount64(x) __builtin_popcountll((uintll)(x))

static inline u32 encrypt32 (u32 x, const u32 mask) {

    uint q = popcount32(mask);

    x += mask;
    x = (x >> q) | (x << (32 - q));

    return x;
}

static inline u32 decrypt32 (u32 x, const u32 mask) {

    uint q = popcount32(mask);

    x = (x << q) | (x >> (32 - q));
    x -= mask;

    return x;
}

static inline u64 encrypt64 (u64 x, const u64 mask) {

    uint q = popcount64(mask);

    x += mask;
    x = (x >> q) | (x << (64 - q));

    return x;
}

static inline u64 decrypt64 (u64 x, const u64 mask) {

    uint q = popcount64(mask);

    x = (x << q) | (x >> (64 - q));
    x -= mask;

    return x;
}

#define XTUN_CRYPTO_PARAMS_SIZE 32

typedef union xtun_crypto_params_s { char _[XTUN_CRYPTO_PARAMS_SIZE];
#if XGW_XTUN_CRYPTO_ALGO_NULL0
	// NOTHING
#endif
#if XGW_XTUN_CRYPTO_ALGO_NULLX
    struct xtun_crypto_params_nullx_s {
        u64 x;
    } nullx;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
    struct xtun_crypto_params_shift32_1_s {
        u32 k[1];
    } shift32_1;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
    struct xtun_crypto_params_shift64_1_s {
        u64 k[1];
    } shift64_1;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
    struct xtun_crypto_params_shift64_2_s {
        u64 k[2];
    } shift64_2;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
    struct xtun_crypto_params_shift64_3_s {
        u64 k[3];
    } shift64_3;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
    struct xtun_crypto_params_shift64_4_s {
        u64 k[4];
    } shift64_4;
#endif
} xtun_crypto_params_s;

#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
static u16 xtun_crypto_shift32_1_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k0 = params->shift32_1.k[0] + XTUN_CRYPTO_SHIFT32_KEY_0_ADD;

    k0 += encrypt32(0x3223232U, size);

    data += size;

    while (size >= sizeof(u32)) {

        size -= sizeof(u32);
        data -= sizeof(u32);

        const u32 orig = BE32(*(u32*)data);

        u32 value = orig;

        value = encrypt32(value, size);
        value = encrypt32(value, k0);

        *(u32*)data = BE32(value);

        k0 += encrypt32(orig, size);
        k0 += encrypt32(size, size);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        const u8 orig = BE8(*(u8*)data);

        u32 value = orig;

        value += encrypt32(k0, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        k0 += encrypt32(orig, size);
        k0 += encrypt32(size, size);
    }

    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}

static u16 xtun_crypto_shift32_1_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k0 = params->shift32_1.k[0] + XTUN_CRYPTO_SHIFT32_KEY_0_ADD;

    k0 += encrypt32(0x3223232U, size);

    data += size;

    while (size >= sizeof(u32)) {

        size -= sizeof(u32);
        data -= sizeof(u32);

        u32 orig = BE32(*(u32*)data);

        orig = decrypt32(orig, k0);
        orig = decrypt32(orig, size);

        *(u32*)data = BE32(orig);

        k0 += encrypt32(orig, size);
        k0 += encrypt32(size, size);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        u32 orig = BE8(*(u8*)data);

        orig -= encrypt32(k0, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        k0 += encrypt32(orig, size);
        k0 += encrypt32(size, size);
    }

    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}
#endif


#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
static u16 xtun_crypto_shift64_1_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k0 = params->shift64_1.k[0] + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;

    k0 += encrypt64(0x32234235232ULL, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value = encrypt64(value, size);
        value = encrypt64(value, k0);

        *(u64*)data = BE64(value);

        k0 += encrypt64(orig, size);
        k0 += encrypt64(size, size);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += encrypt64(k0, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        k0 += encrypt64(orig, size);
        k0 += encrypt64(size, size);
    }

    k0 += k0 >> 32;
    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}

static u16 xtun_crypto_shift64_1_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k0 = params->shift64_1.k[0] + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;

    k0 += encrypt64(0x32234235232ULL, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        u64 orig = BE64(*(u64*)data);

        orig = decrypt64(orig, k0);
        orig = decrypt64(orig, size);

        *(u64*)data = BE64(orig);

        k0 += encrypt64(orig, size);
        k0 += encrypt64(size, size);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        u64 orig = BE8(*(u8*)data);

        orig -= encrypt64(k0, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        k0 += encrypt64(orig, size);
        k0 += encrypt64(size, size);
    }

    k0 += k0 >> 32;
    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
static u16 xtun_crypto_shift64_4_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k0 = params->shift64_4.k[0] + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;
    u64 k1 = params->shift64_4.k[1] + XTUN_CRYPTO_SHIFT64_KEY_1_ADD;
    u64 k2 = params->shift64_4.k[2] + XTUN_CRYPTO_SHIFT64_KEY_2_ADD;
    u64 k3 = params->shift64_4.k[3] + XTUN_CRYPTO_SHIFT64_KEY_3_ADD;

    k0 += encrypt64(k3, size);
    k1 += encrypt64(k2, size);
    k2 += encrypt64(k1, size);
    k3 += encrypt64(k0, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value = encrypt64(value, size);
        value = encrypt64(value, k0);
        value = encrypt64(value, k1);
        value = encrypt64(value, k2);
        value = encrypt64(value, k3);

        *(u64*)data = BE64(value);

        k0 += encrypt64(k3, orig);
        k1 += encrypt64(k0, size);
        k2 += encrypt64(orig, k1);
        k3 += encrypt64(orig, k2);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += encrypt64(k0, size);
        value += encrypt64(k1, size);
        value += encrypt64(k2, size);
        value += encrypt64(k3, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        k0 += encrypt64(k1, orig);
        k1 += encrypt64(orig, k0);
    }

    k0 += k1;
    k0 += k2;
    k0 += k3;
    k0 += k0 >> 32;
    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}

static u16 xtun_crypto_shift64_4_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k0 = params->shift64_4.k[0] + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;
    u64 k1 = params->shift64_4.k[1] + XTUN_CRYPTO_SHIFT64_KEY_1_ADD;
    u64 k2 = params->shift64_4.k[2] + XTUN_CRYPTO_SHIFT64_KEY_2_ADD;
    u64 k3 = params->shift64_4.k[3] + XTUN_CRYPTO_SHIFT64_KEY_3_ADD;

    k0 += encrypt64(k3, size);
    k1 += encrypt64(k2, size);
    k2 += encrypt64(k1, size);
    k3 += encrypt64(k0, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        u64 orig = BE64(*(u64*)data);

        orig = decrypt64(orig, k3);
        orig = decrypt64(orig, k2);
        orig = decrypt64(orig, k1);
        orig = decrypt64(orig, k0);
        orig = decrypt64(orig, size);

        *(u64*)data = BE64(orig);

        k0 += encrypt64(k3, orig);
        k1 += encrypt64(k0, size);
        k2 += encrypt64(orig, k1);
        k3 += encrypt64(orig, k2);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        u64 orig = BE8(*(u8*)data);

        orig -= encrypt64(k3, size);
        orig -= encrypt64(k2, size);
        orig -= encrypt64(k1, size);
        orig -= encrypt64(k0, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        k0 += encrypt64(k1, orig);
        k1 += encrypt64(orig, k0);
    }

    k0 += k1;
    k0 += k2;
    k0 += k3;
    k0 += k0 >> 32;
    k0 += k0 >> 16;
    k0 &= 0xFFFFULL;

    return (u16)k0;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_NULL0
static u16 xtun_crypto_null0_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_null0_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_NULLX
static u16 xtun_crypto_nullx_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_nullx_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_SUM32
static u16 xtun_crypto_sum32_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_sum32_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_SUM64
static u16 xtun_crypto_sum64_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_sum64_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

typedef enum xtun_crypto_algo_e {
#if XGW_XTUN_CRYPTO_ALGO_NULL0
        XTUN_CRYPTO_ALGO_NULL0,
#endif
#if XGW_XTUN_CRYPTO_ALGO_NULLX
        XTUN_CRYPTO_ALGO_NULLX,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM32
        XTUN_CRYPTO_ALGO_SUM32,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM64
        XTUN_CRYPTO_ALGO_SUM64,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
        XTUN_CRYPTO_ALGO_SHIFT32_1,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
        XTUN_CRYPTO_ALGO_SHIFT64_1,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
        XTUN_CRYPTO_ALGO_SHIFT64_2,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
        XTUN_CRYPTO_ALGO_SHIFT64_3,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
        XTUN_CRYPTO_ALGO_SHIFT64_4,
#endif
        XTUN_CRYPTO_ALGOS_N
} xtun_crypto_algo_e;

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
typedef u16 (*xtun_crypto_decode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);
typedef u16 (*xtun_crypto_encode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);

static const xtun_crypto_decode_f xtun_crypto_decode[XTUN_CRYPTO_ALGOS_N] = {
#if XGW_XTUN_CRYPTO_ALGO_NULL0
       [XTUN_CRYPTO_ALGO_NULL0]      = xtun_crypto_null0_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_NULLX
       [XTUN_CRYPTO_ALGO_NULLX]      = xtun_crypto_nullx_decode, // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM32
       [XTUN_CRYPTO_ALGO_SUM32]      = xtun_crypto_sum32_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM64
       [XTUN_CRYPTO_ALGO_SUM64]      = xtun_crypto_sum64_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
       [XTUN_CRYPTO_ALGO_SHIFT32_1]  = xtun_crypto_shift32_1_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
       [XTUN_CRYPTO_ALGO_SHIFT64_1]  = xtun_crypto_shift64_1_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
       [XTUN_CRYPTO_ALGO_SHIFT64_2]  = xtun_crypto_shift64_2_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
       [XTUN_CRYPTO_ALGO_SHIFT64_3]  = xtun_crypto_shift64_3_decode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
       [XTUN_CRYPTO_ALGO_SHIFT64_4]  = xtun_crypto_shift64_4_decode,
#endif
};

static const xtun_crypto_encode_f xtun_crypto_encode[XTUN_CRYPTO_ALGOS_N] = {
#if XGW_XTUN_CRYPTO_ALGO_NULL0
       [XTUN_CRYPTO_ALGO_NULL0]      = xtun_crypto_null0_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_NULLX
       [XTUN_CRYPTO_ALGO_NULLX]      = xtun_crypto_nullx_encode, // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM32
       [XTUN_CRYPTO_ALGO_SUM32]      = xtun_crypto_sum32_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SUM64
       [XTUN_CRYPTO_ALGO_SUM64]      = xtun_crypto_sum64_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
       [XTUN_CRYPTO_ALGO_SHIFT32_1]  = xtun_crypto_shift32_1_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
       [XTUN_CRYPTO_ALGO_SHIFT64_1]  = xtun_crypto_shift64_1_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
       [XTUN_CRYPTO_ALGO_SHIFT64_2]  = xtun_crypto_shift64_2_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
       [XTUN_CRYPTO_ALGO_SHIFT64_3]  = xtun_crypto_shift64_3_encode,
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
       [XTUN_CRYPTO_ALGO_SHIFT64_4]  = xtun_crypto_shift64_4_encode,
#endif
};

#define xtun_crypto_encode(algo, params, data, size) xtun_crypto_encode[algo](params, data, size)
#define xtun_crypto_decode(algo, params, data, size) xtun_crypto_decode[algo](params, data, size)
