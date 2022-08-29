
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

static inline u64 swap64 (const u64 x, const uint q) {

    return (x >> q) | (x << (64 - q));
}

static inline u64 swap64_undo (const u64 x, const uint q) {

    return (x << q) | (x >> (64 - q));
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* pos, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += swap64(key, (size % 64));
    key += swap64(sec, (size % 64));

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)pos);

        u64 value = orig;

        value += key;
        value ^= sec;
        value = swap64(value, (key + sec + size) % 64);

        *(u64*)pos = BE64(value);

        key += sec >> (size % 64);
        sec += orig >> (key % 64);

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
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;    
    sec += !sec;

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_decode (u64 sec, u64 key, void* pos, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += swap64(key, (size % 64));
    key += swap64(sec, (size % 64));

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)pos);

        u64 orig = value;

        orig = swap64_undo(orig, (key + sec + size) % 64);
        orig ^= sec;        
        orig -= key;

        *(u64*)pos = BE64(orig);

        key += sec >> (size % 64);
        sec += orig >> (key % 64);

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
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;    
    sec += !sec;

    return sec;
}
