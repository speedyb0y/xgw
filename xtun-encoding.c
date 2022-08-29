
#define ENCODING_INIT_KEY_ADD XGW_XTUN_ENCODING_INIT_KEY_ADD
#define ENCODING_INIT_SEC_ADD XGW_XTUN_ENCODING_INIT_SEC_ADD

#if ENCODING_INIT_SEC_ADD <= 0 \
 || ENCODING_INIT_SEC_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_INIT_SEC_ADD"
#endif

#if ENCODING_INIT_KEY_ADD <= 0 \
 || ENCODING_INIT_KEY_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_INIT_KEY_ADD"
#endif

#define BE8(x) (x)
#define BE64(x)(x) // TODO: FIXME:

// PEGA UM MENOR E TRANSFORMA EM UM MAIOR
static inline u64 U16_AS_U64 (u64 x) {

    x |= x << 16;
    x |= x << 32;

    return x;
}

// PEGA UM MAIOR E TRANSFORMA EM UM MENOR
static inline u16 U64_AS_U16 (u64 x) {

    x += x >> 32;
    x += x >> 16;
    x &= 0xFFFFULL;

    return (u16)x;
}

#define SECRET16(s) U16_AS_U64(s)
#define SECRET32(s) U32_AS_U64(s)
#define SECRET64(s)           (s)

#define KEY16(k) U16_AS_U64(k)
#define KEY32(k) U32_AS_U64(k)
#define KEY64(k)           (k)

#define HASH16(h) U64_AS_U16(h)
#define HASH32(h) U64_AS_U32(h)
#define HASH64(h)           (h)

static inline u64 swap64 (const u64 x, const uint q) {

    return (x >> q) | (x << (64 - q));
}

static inline u64 swap64_undo (const u64 x, const uint q) {

    return (x << q) | (x >> (64 - q));
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* pos, uint size) {

    sec += ENCODING_INIT_SEC_ADD;
    key += ENCODING_INIT_KEY_ADD;

    sec += swap64(key, (size % 64));
    key += swap64(sec, (size % 64));

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)pos);

        u64 value = orig;

        value += key;
        value += sec;
        value = swap64(value, ((key ^ sec) + size) % 63);

        *(u64*)pos = BE64(value);

        sec += orig >> (key % 64);
        key += sec >> (size % 64);
        key ^= orig;

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 orig = BE8(*(u8*)pos);

        u8 value = orig;

        value += sec;

        *(u8*)pos = BE8(value);

        sec <<= 1;
        sec += orig;

        pos  += sizeof(u8);
        size -= sizeof(u8);
    }

    sec += key;
    sec += !sec;

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_decode (u64 sec, u64 key, void* pos, uint size) {

    sec += ENCODING_INIT_SEC_ADD;
    key += ENCODING_INIT_KEY_ADD;

    sec += swap64(key, (size % 64));
    key += swap64(sec, (size % 64));

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)pos);

        u64 orig = value;

        orig = swap64_undo(orig, ((key ^ sec) + size) % 63);
        orig -= sec;        
        orig -= key;

        *(u64*)pos = BE64(orig);

        sec += orig >> (key % 64);
        key += sec >> (size % 64);
        key ^= orig;

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 value = BE8(*(u8*)pos);

        u8 orig = value;

        orig -= sec;

        *(u8*)pos = BE8(orig);

        sec <<= 1;
        sec += orig;

        pos  += sizeof(u8);
        size -= sizeof(u8);
    }

    sec += key;
    sec += !sec;

    return sec;
}
