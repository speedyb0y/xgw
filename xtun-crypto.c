
#define XTUN_KEYS_N XGW_XTUN_KEYS_N

#define XTUN_CRYPTO_SHIFT64_KEY_0_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_0_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_1_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_1_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_3_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_3_ADD
#define XTUN_CRYPTO_SHIFT64_KEY_4_ADD XGW_XTUN_CRYPTO_SHIFT64_KEY_4_ADD

#define XTUN_CRYPTO_ALGO_NULL0     XGW_XTUN_CRYPTO_ALGO_NULL0
#define XTUN_CRYPTO_ALGO_X         XGW_XTUN_CRYPTO_ALGO_X
#define XTUN_CRYPTO_ALGO_SUM32     XGW_XTUN_CRYPTO_ALGO_SUM32
#define XTUN_CRYPTO_ALGO_SUM64     XGW_XTUN_CRYPTO_ALGO_SUM64
#define XTUN_CRYPTO_ALGO_SHIFT64_1 XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
#define XTUN_CRYPTO_ALGO_SHIFT64_2 XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
#define XTUN_CRYPTO_ALGO_SHIFT64_3 XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
#define XTUN_CRYPTO_ALGO_SHIFT64_4 XGW_XTUN_CRYPTO_ALGO_SHIFT64_4

#if XTUN_CRYPTO_SHIFT64_KEY_0_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_0_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_0_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_1_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_1_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_1_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_3_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_3_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_3_ADD"
#endif

#if XTUN_CRYPTO_SHIFT64_KEY_4_ADD <= 0 \
 || XTUN_CRYPTO_SHIFT64_KEY_4_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_CRYPTO_SHIFT64_KEY_4_ADD"
#endif

#define popcount32(x) __builtin_popcount((uint)(x))
#define popcount64(x) __builtin_popcountll((uintll)(x))

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

#if XTUN_CRYPTO_ALGO_SHIFT64_4
typedef struct xtun_crypto_64_4_s {
    u64 a;
    u64 b;
    u64 c;
    u64 d;
} xtun_crypto_64_4_s;

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_crypto_shift64_4_encode (const xtun_crypto_64_4_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->a + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;
    u64 b = params->b + XTUN_CRYPTO_SHIFT64_KEY_1_ADD;
    u64 c = params->c + XTUN_CRYPTO_SHIFT64_KEY_3_ADD;
    u64 d = params->d + XTUN_CRYPTO_SHIFT64_KEY_4_ADD;

    a += encrypt64(d, size);
    b += encrypt64(c, size);
    c += encrypt64(b, size);
    d += encrypt64(a, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value = encrypt64(value, size);
        value = encrypt64(value, a);
        value = encrypt64(value, b);
        value = encrypt64(value, c);
        value = encrypt64(value, d);

        *(u64*)data = BE64(value);

        a += encrypt64(d, orig);
        b += encrypt64(a, size);
        c += encrypt64(orig, b);
        d += encrypt64(orig, c);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += encrypt64(a, size);
        value += encrypt64(b, size);
        value += encrypt64(c, size);
        value += encrypt64(d, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        a += encrypt64(b, orig);
        b += encrypt64(orig, a);
    }

    a += b;
    a += a >> 32;
    a += a >> 16;
    a &= 0xFFFFULL;

    return (u16)a;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_crypto_shift64_4_decode (const xtun_crypto_64_4_s* const restrict params, void* restrict data, uint size) {

    u64 a = params->a + XTUN_CRYPTO_SHIFT64_KEY_0_ADD;
    u64 b = params->b + XTUN_CRYPTO_SHIFT64_KEY_1_ADD;
    u64 c = params->c + XTUN_CRYPTO_SHIFT64_KEY_3_ADD;
    u64 d = params->d + XTUN_CRYPTO_SHIFT64_KEY_4_ADD;

    a += encrypt64(d, size);
    b += encrypt64(c, size);
    c += encrypt64(b, size);
    d += encrypt64(a, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        u64 orig = BE64(*(u64*)data);

        orig = decrypt64(orig, d);
        orig = decrypt64(orig, c);
        orig = decrypt64(orig, b);
        orig = decrypt64(orig, a);
        orig = decrypt64(orig, size);

        *(u64*)data = BE64(orig);

        a += encrypt64(d, orig);
        b += encrypt64(a, size);
        c += encrypt64(orig, b);
        d += encrypt64(orig, c);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        u64 orig = BE8(*(u8*)data);

        orig -= encrypt64(d, size);
        orig -= encrypt64(c, size);
        orig -= encrypt64(b, size);
        orig -= encrypt64(a, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        a += encrypt64(b, orig);
        b += encrypt64(orig, a);
    }

    a += b;
    a += a >> 32;
    a += a >> 16;
    a &= 0xFFFFULL;

    return (u16)a;
}
#endif

#if XTUN_CRYPTO_ALGO_NULL0
typedef struct xtun_crypto_null0_s {
    int _ignored;
} xtun_crypto_null0_s;

static u16 xtun_crypto_null0_encode (const xtun_crypto_null0_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_null0_decode (const xtun_crypto_null0_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

#if XTUN_CRYPTO_ALGO_X
typedef struct xtun_crypto_x_s { u64 x; } xtun_crypto_x_s;

static u16 xtun_crypto_x_encode (const xtun_crypto_x_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_crypto_x_decode (const xtun_crypto_x_s* const restrict params, void* restrict data, uint size) {

    (void)params;
    (void)data;
    (void)size;

    return (u16)0;
}
#endif

enum {
#if XTUN_CRYPTO_ALGO_NULL0
    XTUN_CRYPTO_ALGO_NULL0,
#endif
#if XTUN_CRYPTO_ALGO_X
    XTUN_CRYPTO_ALGO_X,
#endif
#if XTUN_CRYPTO_ALGO_SUM32
    XTUN_CRYPTO_ALGO_SUM32,
#endif
#if XTUN_CRYPTO_ALGO_SUM64
    XTUN_CRYPTO_ALGO_SUM64,
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_1
    XTUN_CRYPTO_ALGO_SHIFT64_1,
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_2
    XTUN_CRYPTO_ALGO_SHIFT64_2,
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_3
    XTUN_CRYPTO_ALGO_SHIFT64_3,
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_4
    XTUN_CRYPTO_ALGO_SHIFT64_4,
#endif
    XTUN_CRYPTO_ALGOS_N
};

#define XTUN_CRYPTO_PARAMS_SIZE 32

typedef union xtun_crypto_params_s { char _[XTUN_CRYPTO_PARAMS_SIZE];
#if XTUN_CRYPTO_ALGO_NULL0
    xtun_crypto_null0_s null0;
#endif
#if XTUN_CRYPTO_ALGO_X
    xtun_crypto_x_s x;
#endif
#if XTUN_CRYPTO_ALGO_SUM32
    xtun_crypto_sum32_s sum32;
#endif
#if XTUN_CRYPTO_ALGO_SUM64
    xtun_crypto_sum64_s sum64;
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_1
    xtun_crypto_64_1_s shift64_1;
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_2
    xtun_crypto_64_2_s shift64_2;
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_3
    xtun_crypto_64_3_s shift64_3;
#endif
#if XTUN_CRYPTO_ALGO_SHIFT64_4
    xtun_crypto_64_4_s shift64_4;
#endif
} xtun_crypto_s;

typedef u16 (*xtun_crypto_encode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);
typedef u16 (*xtun_crypto_decode_f) (const xtun_crypto_params_s* const restrict params, void* const restrict data, uint size);

#define XTUN_CRYPTO_DECODE_F(f) ((xtun_crypto_decode_f)(f))
#define XTUN_CRYPTO_ENCODE_F(f) ((xtun_crypto_encode_f)(f))

static const xtun_crypto_decode_f xtun_crypto_decode[XTUN_CRYPTO_ALGOS_N] = {
#if  XTUN_CRYPTO_ALGO_NULL0
    [XTUN_CRYPTO_ALGO_NULL0]      = XTUN_CRYPTO_DECODE_F(xtun_crypto_0_decode),
#endif
#if  XTUN_CRYPTO_ALGO_X
    [XTUN_CRYPTO_ALGO_X]          = XTUN_CRYPTO_DECODE_F(xtun_crypto_x_decode), // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if  XTUN_CRYPTO_ALGO_SUM32
    [XTUN_CRYPTO_ALGO_SUM32]      = XTUN_CRYPTO_DECODE_F(xtun_crypto_sum32_decode),
#endif
#if  XTUN_CRYPTO_ALGO_SUM64
    [XTUN_CRYPTO_ALGO_SUM64]      = XTUN_CRYPTO_DECODE_F(xtun_crypto_sum64_decode),
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_1
    [XTUN_CRYPTO_ALGO_SHIFT64_1]  = XTUN_CRYPTO_DECODE_F(xtun_crypto_64_1_decode),
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_2
    [XTUN_CRYPTO_ALGO_SHIFT64_2]  = XTUN_CRYPTO_DECODE_F(xtun_crypto_64_2_decode),
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_3
    [XTUN_CRYPTO_ALGO_SHIFT64_3]  = XTUN_CRYPTO_DECODE_F(xtun_crypto_64_3_decode),
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_4
    [XTUN_CRYPTO_ALGO_SHIFT64_4]  = XTUN_CRYPTO_DECODE_F(xtun_crypto_64_4_decode),
#endif
};

static const xtun_crypto_encode_f xtun_crypto_encode[XTUN_CRYPTO_ALGOS_N] = {
#if  XTUN_CRYPTO_ALGO_NULL0
    [XTUN_CRYPTO_ALGO_NULL0]      = xtun_crypto_0_encode,
#endif
#if  XTUN_CRYPTO_ALGO_X
    [XTUN_CRYPTO_ALGO_X]          = xtun_crypto_x_encode, // TODO: FIXME: NESTE MODO SOMENTE COMPUTAR UM CHECKSUM
#endif
#if  XTUN_CRYPTO_ALGO_SUM32
    [XTUN_CRYPTO_ALGO_SUM32]      = xtun_crypto_sum32_encode,
#endif
#if  XTUN_CRYPTO_ALGO_SUM64
    [XTUN_CRYPTO_ALGO_SUM64]      = xtun_crypto_sum64_encode,
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_1
    [XTUN_CRYPTO_ALGO_SHIFT64_1]  = xtun_crypto_64_1_encode,
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_2
    [XTUN_CRYPTO_ALGO_SHIFT64_2]  = xtun_crypto_64_2_encode,
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_3
    [XTUN_CRYPTO_ALGO_SHIFT64_3]  = xtun_crypto_64_3_encode,
#endif
#if  XTUN_CRYPTO_ALGO_SHIFT64_4
    [XTUN_CRYPTO_ALGO_SHIFT64_4]  = xtun_crypto_64_4_encode,
#endif
};
