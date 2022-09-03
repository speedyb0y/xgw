
#define popcount32(x) __builtin_popcount((uint)(x))
#define popcount64(x) __builtin_popcountll((uintll)(x))

static inline u32 swap32 (u32 x, const u32 mask) {

    const uint q = popcount32(mask);

    x += mask;
    x = (x >> q) | (x << (32 - q));

    return x;
}

static inline u32 unswap32 (u32 x, const u32 mask) {

    const uint q = popcount32(mask);

    x = (x << q) | (x >> (32 - q));
    x -= mask;

    return x;
}

static inline u64 swap64 (u64 x, const u64 mask) {

    const uint q = popcount64(mask);

    x += mask;
    x = (x >> q) | (x << (64 - q));

    return x;
}

static inline u64 unswap64 (u64 x, const u64 mask) {

    const uint q = popcount64(mask);

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
        u32 k;
    } shift32_1;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
    struct xtun_crypto_params_shift64_1_s {
        u64 k;
    } shift64_1;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
    struct xtun_crypto_params_shift64_2_s {
        u64 a;
        u64 b;
    } shift64_2;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
    struct xtun_crypto_params_shift64_3_s {
        u64 a;
        u64 b;
        u64 c;
    } shift64_3;
#endif
#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
    struct xtun_crypto_params_shift64_4_s {
        u64 a;
        u64 b;
        u64 c;
        u64 d;
    } shift64_4;
#endif
} xtun_crypto_params_s;

#if XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
static u16 xtun_crypto_shift32_1_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k = params->shift32_1.k;

    k += swap32(k, size);

    data += size;

    while (size >= sizeof(u32)) {
        size -= sizeof(u32);
        data -= sizeof(u32);
        const u32 orig = BE32(*(u32*)data);
        u32 value = orig;
        value = swap32(value, size);
        value = swap32(value, k);
        *(u32*)data = BE32(value);
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        const u8 orig = BE8(*(u8*)data);
        u32 value = orig;
        value += swap32(k, size);
        value &= 0xFFU;
        *(u8*)data = BE8(value);
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}

static u16 xtun_crypto_shift32_1_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k = params->shift32_1.k;

    k += swap32(k, size);

    data += size;

    while (size >= sizeof(u32)) {
        size -= sizeof(u32);
        data -= sizeof(u32);
        u32 orig = BE32(*(u32*)data);
        orig = unswap32(orig, k);
        orig = unswap32(orig, size);
        *(u32*)data = BE32(orig);
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        u32 orig = BE8(*(u8*)data);
        orig -= swap32(k, size);
        orig &= 0xFFU;
        *(u8*)data = BE8(orig);
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}
#endif


#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
static u16 xtun_crypto_shift64_1_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k = params->shift64_1.k;

    k += swap64(k, size);

    data += size;

    while (size >= sizeof(u64)) {
        size -= sizeof(u64);
        data -= sizeof(u64);
        const u64 orig = BE64(*(u64*)data);
        u64 value = orig;
        value = swap64(value, size);
        value = swap64(value, k);
        *(u64*)data = BE64(value);
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        const u8 orig = BE8(*(u8*)data);
        u64 value = orig;
        value += swap64(k, size);
        value &= 0xFFU;
        *(u8*)data = BE8(value);
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    k += k >> 32;
    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}

static u16 xtun_crypto_shift64_1_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k = params->shift64_1.k;

    k += swap64(k, size);

    data += size;

    while (size >= sizeof(u64)) {
        size -= sizeof(u64);
        data -= sizeof(u64);
        u64 orig = BE64(*(u64*)data);
        orig = unswap64(orig, k);
        orig = unswap64(orig, size);
        *(u64*)data = BE64(orig);
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        u64 orig = BE8(*(u8*)data);
        orig -= swap64(k, size);
        orig &= 0xFFU;
        *(u8*)data = BE8(orig);
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    k += k >> 32;
    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}
#endif

#if XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
static u16 xtun_crypto_shift64_4_encode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->shift64_4.a;
    u64 b = params->shift64_4.b;
    u64 c = params->shift64_4.c;
    u64 d = params->shift64_4.d;

    a += swap64(d, size);
    b += swap64(c, size);
    c += swap64(b, size);
    d += swap64(a, size);

    data += size;

    while (size >= sizeof(u64)) {
        size -= sizeof(u64);
        data -= sizeof(u64);
        const u64 orig = BE64(*(u64*)data);
        u64 value = orig;
        value = swap64(value, size);
        value = swap64(value, a);
        value = swap64(value, b);
        value = swap64(value, c);
        value = swap64(value, d);
        *(u64*)data = BE64(value);
        a += swap64(orig, size);
        b += swap64(a, orig);
        c += swap64(b, orig);
        d += swap64(c, orig);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        const u8 orig = BE8(*(u8*)data);
        u64 value = orig;
        value += swap64(a, size);
        value += swap64(b, size);
        value += swap64(c, size);
        value += swap64(d, size);
        value &= 0xFFU;
        *(u8*)data = BE8(value);
        a += swap64(b, orig);
        b += swap64(orig, a);
    }

    a += b;
    a += c;
    a += d;
    a += a >> 32;
    a += a >> 16;
    a &= 0xFFFFULL;

    return (u16)a;
}

static u16 xtun_crypto_shift64_4_decode (const xtun_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->shift64_4.a;
    u64 b = params->shift64_4.b;
    u64 c = params->shift64_4.c;
    u64 d = params->shift64_4.d;

    a += swap64(d, size);
    b += swap64(c, size);
    c += swap64(b, size);
    d += swap64(a, size);

    data += size;

    while (size >= sizeof(u64)) {
        size -= sizeof(u64);
        data -= sizeof(u64);
        u64 orig = BE64(*(u64*)data);
        orig = unswap64(orig, d);
        orig = unswap64(orig, c);
        orig = unswap64(orig, b);
        orig = unswap64(orig, a);
        orig = unswap64(orig, size);
        *(u64*)data = BE64(orig);
        a += swap64(orig, size);
        b += swap64(a, orig);
        c += swap64(b, orig);
        d += swap64(c, orig);
    }

    while (size) {
        size -= sizeof(u8);
        data -= sizeof(u8);
        u64 orig = BE8(*(u8*)data);
        orig -= swap64(d, size);
        orig -= swap64(c, size);
        orig -= swap64(b, size);
        orig -= swap64(a, size);
        orig &= 0xFFU;
        *(u8*)data = BE8(orig);
        a += swap64(b, orig);
        b += swap64(orig, a);
    }

    a += b;
    a += c;
    a += d;
    a += a >> 32;
    a += a >> 16;
    a &= 0xFFFFULL;

    return (u16)a;
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

#if (\
    + XGW_XTUN_CRYPTO_ALGO_NULL0 \
    + XGW_XTUN_CRYPTO_ALGO_NULLX \
    + XGW_XTUN_CRYPTO_ALGO_SUM32 \
    + XGW_XTUN_CRYPTO_ALGO_SUM64 \
    + XGW_XTUN_CRYPTO_ALGO_SHIFT32_1 \
    + XGW_XTUN_CRYPTO_ALGO_SHIFT64_1 \
    + XGW_XTUN_CRYPTO_ALGO_SHIFT64_2 \
    + XGW_XTUN_CRYPTO_ALGO_SHIFT64_3 \
    + XGW_XTUN_CRYPTO_ALGO_SHIFT64_4 \
    ) > 1
// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
typedef u16 (*xtun_crypto_decode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);
typedef u16 (*xtun_crypto_encode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);

static const xtun_crypto_decode_f _xtun_crypto_decode[XTUN_CRYPTO_ALGOS_N] = {
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

static const xtun_crypto_encode_f _xtun_crypto_encode[XTUN_CRYPTO_ALGOS_N] = {
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

#define xtun_crypto_encode(algo, params, data, size) _xtun_crypto_encode[algo](params, data, size)
#define xtun_crypto_decode(algo, params, data, size) _xtun_crypto_decode[algo](params, data, size)
#elif XGW_XTUN_CRYPTO_ALGO_NULL0
#define xtun_crypto_encode xtun_crypto_null0_encode
#define xtun_crypto_decode xtun_crypto_null0_decode
#elif XGW_XTUN_CRYPTO_ALGO_NULLX
#define xtun_crypto_encode xtun_crypto_nullx_encode
#define xtun_crypto_decode xtun_crypto_nullx_decode
#elif XGW_XTUN_CRYPTO_ALGO_SUM32
#define xtun_crypto_encode xtun_crypto_sum32_encode
#define xtun_crypto_decode xtun_crypto_sum32_decode
#elif XGW_XTUN_CRYPTO_ALGO_SUM64
#define xtun_crypto_encode xtun_crypto_sum64_encode
#define xtun_crypto_decode xtun_crypto_sum64_decode
#elif XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
#define xtun_crypto_encode xtun_crypto_shift32_1_encode
#define xtun_crypto_decode xtun_crypto_shift32_1_decode
#elif XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
#define xtun_crypto_encode xtun_crypto_shift64_1_encode
#define xtun_crypto_decode xtun_crypto_shift64_1_decode
#elif XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
#define xtun_crypto_encode xtun_crypto_shift64_2_encode
#define xtun_crypto_decode xtun_crypto_shift64_2_decode
#elif XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
#define xtun_crypto_encode xtun_crypto_shift64_3_encode
#define xtun_crypto_decode xtun_crypto_shift64_3_decode
#elif XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
#define xtun_crypto_encode xtun_crypto_shift64_4_encode
#define xtun_crypto_decode xtun_crypto_shift64_4_decode
#else
#error
#endif
