
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

static inline u64 swap64 (u64 x, const u64 mask) {

	uint q = popcount64(mask);

	x += mask;
	x = (x >> q) | (x << (64 - q));

    return x;
}

static inline u64 swap64_undo (u64 x, const u64 mask) {

	uint q = popcount64(mask);

	x = (x << q) | (x >> (64 - q));
	x -= mask;

    return x;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* data, uint size) {

    sec += ENCODING_SEC_ADD;
    key += ENCODING_KEY_ADD;

    sec += swap64(key, size);
    key += swap64(sec, size);

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)data);

        u64 value = orig;

        value = swap64(value, size);
        value = swap64(value, sec);
        value = swap64(value, key);

        *(u64*)data = BE64(value);

        sec += swap64(key, orig);
        key += swap64(orig, sec);

        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 orig = BE8(*(u8*)data);

        u64 value = orig;

        value += swap64(sec, size);
        value += swap64(key, size);
        value &= 0xFFU;

        *(u8*)data = BE8(value);

        sec += swap64(key, orig);
        key += swap64(orig, sec);

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

    sec += swap64(key, size);
    key += swap64(sec, size);

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)data);

        u64 orig = value;

        orig = swap64_undo(orig, key);
        orig = swap64_undo(orig, sec);
        orig = swap64_undo(orig, size);

        *(u64*)data = BE64(orig);

        sec += swap64(key, orig);
        key += swap64(orig, sec);

        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {

        const u8 value = BE8(*(u8*)data);

        u64 orig = value;

        orig -= swap64(key, size);
        orig -= swap64(sec, size);
        orig &= 0xFFU;

        *(u8*)data = BE8(orig);

        sec += swap64(key, orig);
        key += swap64(orig, sec);

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
