
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

#define XGW_CRYPTO_PARAMS_SIZE 32

typedef union xgw_crypto_params_s {
     char str[XGW_CRYPTO_PARAMS_SIZE/sizeof(char)];
        u8 w8[XGW_CRYPTO_PARAMS_SIZE/sizeof(u8)];
      u16 w16[XGW_CRYPTO_PARAMS_SIZE/sizeof(u16)];
      u32 w32[XGW_CRYPTO_PARAMS_SIZE/sizeof(u32)];
      u64 w64[XGW_CRYPTO_PARAMS_SIZE/sizeof(u64)];
} xgw_crypto_params_s;

#if XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
static u16 xgw_crypto_shift32_1_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k = params->w32[0]
          + params->w32[1]
          + params->w32[2]
          + params->w32[3]
          + params->w32[4]
          + params->w32[5]
          + params->w32[6]
          + params->w32[7]
    ;

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
        const u8 orig = *(u8*)data;
        u32 value = orig;
        value += swap32(k, size);
        value &= 0xFFU;
        *(u8*)data = value;
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}

static u16 xgw_crypto_shift32_1_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u32 k = params->w32[0]
          + params->w32[1]
          + params->w32[2]
          + params->w32[3]
          + params->w32[4]
          + params->w32[5]
          + params->w32[6]
          + params->w32[7]
    ;

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
        u32 orig = *(u8*)data;
        orig -= swap32(k, size);
        orig &= 0xFFU;
        *(u8*)data = orig;
        k += swap32(k, orig);
        k += swap32(orig, k);
    }

    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}
#endif


#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
static u16 xgw_crypto_shift64_1_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k = params->w64[0]
          + params->w64[1]
          + params->w64[2]
          + params->w64[3]
    ;

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
        const u8 orig = *(u8*)data;
        u64 value = orig;
        value += swap64(k, size);
        value &= 0xFFU;
        *(u8*)data = value;
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    k += k >> 32;
    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}

static u16 xgw_crypto_shift64_1_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 k = params->w64[0]
          + params->w64[1]
          + params->w64[2]
          + params->w64[3]
    ;

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
        u64 orig = *(u8*)data;
        orig -= swap64(k, size);
        orig &= 0xFFU;
        *(u8*)data = orig;
        k += swap64(orig, k);
        k += swap64(k, orig);
    }

    k += k >> 32;
    k += k >> 16;
    k &= 0xFFFFULL;

    return (u16)k;
}
#endif

#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
static u16 xgw_crypto_shift64_4_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->w64[0];
    u64 b = params->w64[1];
    u64 c = params->w64[2];
    u64 d = params->w64[3];

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
        const u8 orig = *(u8*)data;
        u64 value = orig;
        value += swap64(a, size);
        value += swap64(b, size);
        value += swap64(c, size);
        value += swap64(d, size);
        value &= 0xFFU;
        *(u8*)data = value;
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

static u16 xgw_crypto_shift64_4_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->w64[0];
    u64 b = params->w64[1];
    u64 c = params->w64[2];
    u64 d = params->w64[3];

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
        u64 orig = *(u8*)data;
        orig -= swap64(d, size);
        orig -= swap64(c, size);
        orig -= swap64(b, size);
        orig -= swap64(a, size);
        orig &= 0xFFU;
        *(u8*)data = orig;
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

#if XCONF_XGW_CRYPTO_ALGO_NULL0
static u16 xgw_crypto_null0_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xgw_crypto_null0_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XCONF_XGW_CRYPTO_ALGO_NULLX
static u16 xgw_crypto_nullx_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xgw_crypto_nullx_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XCONF_XGW_CRYPTO_ALGO_SUM32
static u16 xgw_crypto_sum32_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xgw_crypto_sum32_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XCONF_XGW_CRYPTO_ALGO_SUM64
static u16 xgw_crypto_sum64_encode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xgw_crypto_sum64_decode (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

typedef enum xgw_crypto_algo_e {
#if XCONF_XGW_CRYPTO_ALGO_NULL0
          XGW_CRYPTO_ALGO_NULL0,
#endif
#if XCONF_XGW_CRYPTO_ALGO_NULLX
          XGW_CRYPTO_ALGO_NULLX,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM32
          XGW_CRYPTO_ALGO_SUM32,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM64
          XGW_CRYPTO_ALGO_SUM64,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
          XGW_CRYPTO_ALGO_SHIFT32_1,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
          XGW_CRYPTO_ALGO_SHIFT64_1,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
          XGW_CRYPTO_ALGO_SHIFT64_2,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
          XGW_CRYPTO_ALGO_SHIFT64_3,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
          XGW_CRYPTO_ALGO_SHIFT64_4,
#endif
} xgw_crypto_algo_e;

#define XGW_CRYPTO_ALGOS_N ( \
     XCONF_XGW_CRYPTO_ALGO_NULL0 \
   + XCONF_XGW_CRYPTO_ALGO_NULLX \
   + XCONF_XGW_CRYPTO_ALGO_SUM32 \
   + XCONF_XGW_CRYPTO_ALGO_SUM64 \
   + XCONF_XGW_CRYPTO_ALGO_SHIFT32_1 \
   + XCONF_XGW_CRYPTO_ALGO_SHIFT64_1 \
   + XCONF_XGW_CRYPTO_ALGO_SHIFT64_2 \
   + XCONF_XGW_CRYPTO_ALGO_SHIFT64_3 \
   + XCONF_XGW_CRYPTO_ALGO_SHIFT64_4 \
    )

#if XGW_CRYPTO_ALGOS_N > 1
// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
typedef u16 (*xgw_crypto_encode_f) (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size);
typedef u16 (*xgw_crypto_decode_f) (const xgw_crypto_params_s* const restrict params, void* restrict data, uint size);

static const xgw_crypto_decode_f _xgw_decode [XGW_CRYPTO_ALGOS_N] = {
#if XCONF_XGW_CRYPTO_ALGO_NULL0
               xgw_crypto_null0_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_NULLX
               xgw_crypto_nullx_decode, // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM32
               xgw_crypto_sum32_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM64
               xgw_crypto_sum64_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
               xgw_crypto_shift32_1_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
               xgw_crypto_shift64_1_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
               xgw_crypto_shift64_2_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
               xgw_crypto_shift64_3_decode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
               xgw_crypto_shift64_4_decode,
#endif
};

static const xgw_crypto_encode_f _xgw_encode [XGW_CRYPTO_ALGOS_N] = {
#if XCONF_XGW_CRYPTO_ALGO_NULL0
               xgw_crypto_null0_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_NULLX
               xgw_crypto_nullx_encode, // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM32
               xgw_crypto_sum32_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SUM64
               xgw_crypto_sum64_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
               xgw_crypto_shift32_1_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
               xgw_crypto_shift64_1_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
               xgw_crypto_shift64_2_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
               xgw_crypto_shift64_3_encode,
#endif
#if XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
               xgw_crypto_shift64_4_encode,
#endif
};

#define xgw_crypto_encode(algo, params, data, size) _xgw_encode[algo](params, data, size)
#define xgw_crypto_decode(algo, params, data, size) _xgw_decode[algo](params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_NULL0
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_null0_encode(data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_null0_decode(data, size)
#elif XCONF_XGW_CRYPTO_ALGO_NULLX
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_nullx_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_nullx_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SUM32
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_sum32_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_sum32_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SUM64
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_sum64_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_sum64_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_shift32_1_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_shift32_1_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_shift64_1_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_shift64_1_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_shift64_2_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_shift64_2_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_shift64_3_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_shift64_3_decode(params, data, size)
#elif XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
#define xgw_crypto_encode(algo, params, data, size) xgw_crypto_shift64_4_encode(params, data, size)
#define xgw_crypto_decode(algo, params, data, size) xgw_crypto_shift64_4_decode(params, data, size)
#endif
