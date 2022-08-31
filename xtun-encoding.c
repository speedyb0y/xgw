
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

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_encode (u64 sec, u64 key, void* data, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += encrypt64(key, size);
    key += encrypt64(sec, size);

    data += size;

    while (size >= sizeof(u64)) {
     
        size -= sizeof(u64);
        data -= sizeof(u64);

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value = encrypt64(value, size);
        value = encrypt64(value, sec);
        value = encrypt64(value, key);

        *(u64*)data = BE64(value);

        sec += encrypt64(key, orig);
        key += encrypt64(orig, sec);
    }

    while (size) {
     
        size -= sizeof(u8);
        data -= sizeof(u8);

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += encrypt64(sec, size);
        value += encrypt64(key, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        sec += encrypt64(key, orig);
        key += encrypt64(orig, sec);
    }

    sec += key;
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;
    sec += !sec;

    return (u16)sec;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_decode (u64 sec, u64 key, void* data, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += encrypt64(key, size);
    key += encrypt64(sec, size);

    data += size;

    while (size >= sizeof(u64)) {

        size -= sizeof(u64);
        data -= sizeof(u64);

        u64 orig = BE64(*(u64*)data);

        orig = decrypt64(orig, key);
        orig = decrypt64(orig, sec);
        orig = decrypt64(orig, size);

        *(u64*)data = BE64(orig);

        sec += encrypt64(key, orig);
        key += encrypt64(orig, sec);
    }

    while (size) {

        size -= sizeof(u8);
        data -= sizeof(u8);

        u64 orig = BE8(*(u8*)data);

        orig -= encrypt64(key, size);
        orig -= encrypt64(sec, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        sec += encrypt64(key, orig);
        key += encrypt64(orig, sec);
    }

    sec += key;
    sec += sec >> 32;
    sec += sec >> 16;
    sec &= 0xFFFFULL;
    sec += !sec;

    return (u16)sec;
}
