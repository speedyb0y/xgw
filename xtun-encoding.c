
#define ENCODING_ORIG_ADD XGW_XTUN_ENCODING_BYTE_X

#define ENCODING_INIT_KEY_ADD     0x565640460654ULL
#define ENCODING_INIT_SEC_ADD     XGW_XTUN_ENCODING_INIT_SEC_ADD

#define ENCODING_ROUND_KEY_ADD    0x563343EF0654ULL
#define ENCODING_ROUND_SEC_ADD    0x56564B295654ULL

#if ENCODING_ORIG_ADD <= 0 \
 || ENCODING_ORIG_ADD >= 0xFFFFFFFFFFFFFFFF
#error "BAD ORIG ADD"
#endif

#if ENCODING_INIT_SEC_ADD <= 0 \
 || ENCODING_INIT_SEC_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD SECRET ADD"
#endif

#define BE64(x)(x) // TODO: FIXME:

// PEGA UM MENOR E TRANSFORMA EM UM MAIOR
static inline u64 U16_AS_U64 (u64 x) {

    x |= x << 16;
    x |= x << 32;

    return x;
}

#define SECRET16 U16_AS_U64
#define SECRET32 U32_AS_U64

#define KEY16 U16_AS_U64
#define KEY32 U32_AS_U64

static inline u64 swap64 (const u64 x, const uint q) {

    const u64 a = x & ((1ULL << q) - 1ULL);
    const u64 b = x >> q;

    return (a << (64 - q)) | b;
}

static inline u64 swap64_undo (const u64 x, uint q) {

    q = 64 - q;

    const u64 a = x & ((1ULL << q) - 1ULL);
    const u64 b = x >> q;

    return (a << (64 - q)) | b;
}

// U64 -> U16 ; 0 -> 1
static inline u16 xtun_encoding_hash16 (u64 hash) {

    hash += hash >> 32;
    hash += hash >> 16;
    hash &= 0xFFFFU;

    return (u16)hash;
}

static inline u64 xtun_encoding_init_key (u64 sec, u64 key, uint size) {

    key += ENCODING_INIT_KEY_ADD;
    key += sec << (size % 64);

    return key;
}

static inline u64 xtun_encoding_init_sec (u64 sec, u64 key, uint size) {

    sec += ENCODING_INIT_SEC_ADD;
    sec += key << (size % 64);

    return sec;
}

static inline u64 xtun_encoding_round_key (u64 sec, u64 key, uint size, u8 orig) {

    key += ENCODING_ROUND_KEY_ADD;
    key += sec << ((orig + size) % 64);

    return key;
}

static inline u64 xtun_encoding_round_sec (u64 sec, u64 key, uint size, u8 orig) {

    sec += ENCODING_ROUND_SEC_ADD;
    sec += key << ((orig + size) % 64);

    return sec;
}

static inline u64 xtun_encoding_finish_hash (u64 sec, u64 key) {

    sec += key;
    // SE FOR 0, TRANSFORMA EM 1
    sec += !sec;

    return sec;
}

#define Q(sec, key, size) ((sec + key + size) % 64)

static inline u64 e (u64 sec, u64 key, uint size, u64 x) {

    x += ENCODING_ORIG_ADD;
    x = swap64(x, Q(sec, key, size));

    return x;
}

static inline u64 d (u64 sec, u64 key, uint size, u64 x) {

    x = swap64_undo(x, Q(sec, key, size));
    x -= ENCODING_ORIG_ADD;

    return x;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* pos, uint size) {

    sec = xtun_encoding_init_sec(sec, key, size);
    key = xtun_encoding_init_key(sec, key, size);

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)pos);

        const u64 value = e(sec, key, size, orig);

        *(u64*)pos = BE64(value);

        sec = xtun_encoding_round_sec(sec, key, size, orig);
        key = xtun_encoding_round_key(sec, key, size, orig);

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size--) {

    }

    return xtun_encoding_finish_hash(sec, key);
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_decode (u64 sec, u64 key, void* pos, uint size) {

    sec = xtun_encoding_init_sec(sec, key, size);
    key = xtun_encoding_init_key(sec, key, size);

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)pos);

        const u64 orig = d(sec, key, size, value);

        *(u64*)pos = BE64(orig);

        sec = xtun_encoding_round_sec(sec, key, size, orig);
        key = xtun_encoding_round_key(sec, key, size, orig);

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size--) {

    }

    return xtun_encoding_finish_hash(sec, key);
}
