
#define ENCODING_KEY_ADD XGW_XTUN_ENCODING_KEY_ADD
#define ENCODING_SEC_ADD XGW_XTUN_ENCODING_SEC_ADD

#if ENCODING_SEC_ADD <= 0 \
 || ENCODING_SEC_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_SEC_ADD"
#endif

#if ENCODING_KEY_ADD <= 0 \
 || ENCODING_KEY_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_KEY_ADD"
#endif

#define popcount32(x) __builtin_popcount((uint)(x))
#define popcount64(x) __builtin_popcountll((uintll)(x))

static inline u64 swap64 (const u64 x, const uint q) {

    return (x >> q) | (x << (64 - q));
}

static inline u64 swap64_undo (const u64 x, const uint q) {

    return (x << q) | (x >> (64 - q));
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* data, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += swap64(key, popcount32(size));
    key += swap64(sec, popcount32(size));

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value  = swap64(value, popcount32(size));
        value += key;
        value  = swap64(value, popcount64(sec));
        value += sec;
        value  = swap64(value, popcount64(key));

        *(u64*)data = BE64(value);

        sec += swap64(key, popcount64(orig));
        key += orig;

        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += sec;
        value ^= key;
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        sec += swap64(key, popcount64(orig));
        key += orig;

        data += sizeof(u8);
        size -= sizeof(u8);
    }

    sec += key;
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;
    sec += !sec;

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_decode (u64 sec, u64 key, void* data, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += swap64(key, popcount32(size));
    key += swap64(sec, popcount32(size));

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)data);

        u64 orig = value;

        orig  = swap64_undo(orig, popcount64(key));
        orig -= sec;
        orig  = swap64_undo(orig, popcount64(sec));
        orig -= key;
        orig  = swap64_undo(orig, popcount32(size));

        *(u64*)data = BE64(orig);

        sec += swap64(key, popcount64(orig));
        key += orig;

        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 value = BE8(*(u8*)data);

        u64 orig = value;

        orig ^= key;
        orig -= sec;
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        sec += swap64(key, popcount64(orig));
        key += orig;

        data += sizeof(u8);
        size -= sizeof(u8);
    }

    sec += key;
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;
    sec += !sec;

    return sec;
}
