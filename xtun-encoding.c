
#define ENCODING_ORIG_ADD XGW_XTUN_ENCODING_ORIG_ADD

#define ENCODING_INIT_KEY_ADD XGW_XTUN_ENCODING_INIT_KEY_ADD
#define ENCODING_INIT_SEC_ADD XGW_XTUN_ENCODING_INIT_SEC_ADD

#define ENCODING_ROUND_KEY_ADD XGW_XTUN_ENCODING_ROUND_KEY_ADD
#define ENCODING_ROUND_SEC_ADD XGW_XTUN_ENCODING_ROUND_SEC_ADD

#if ENCODING_ORIG_ADD <= 0 \
 || ENCODING_ORIG_ADD >= 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_ORIG_ADD"
#endif

#if ENCODING_INIT_SEC_ADD <= 0 \
 || ENCODING_INIT_SEC_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_INIT_SEC_ADD"
#endif

#if ENCODING_INIT_KEY_ADD <= 0 \
 || ENCODING_INIT_KEY_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_INIT_KEY_ADD"
#endif

#if ENCODING_ROUND_SEC_ADD <= 0 \
 || ENCODING_ROUND_SEC_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_ROUND_SEC_ADD"
#endif

#if ENCODING_ROUND_KEY_ADD <= 0 \
 || ENCODING_ROUND_KEY_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD ENCODING_ROUND_KEY_ADD"
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

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, void* pos, uint size) {

    key += ENCODING_INIT_KEY_ADD;
    sec += ENCODING_INIT_SEC_ADD;
    
    key += swap64(key, (sec % 64));
    sec += swap64(sec, (key % 64));

    while (size >= sizeof(u64)) {

        const u64 orig = BE64(*(u64*)pos);
        
        u64 value = orig;

		value += sec;
		value = swap64(value, (key % 64));

        *(u64*)pos = BE64(value);

		sec <<= 1;
		sec += key;
		key += orig;

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size--) {

    }

    sec += key;
    sec += !sec;

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_decode (u64 sec, u64 key, void* pos, uint size) {

    key += ENCODING_INIT_KEY_ADD;
    sec += ENCODING_INIT_SEC_ADD;
    
    key += swap64(key, (sec % 64));
    sec += swap64(sec, (key % 64));

    while (size >= sizeof(u64)) {

        const u64 value = BE64(*(u64*)pos);

        u64 orig = value;
        
		orig = swap64_undo(orig, (key % 64));
		orig -= sec;

        *(u64*)pos = BE64(orig);

		sec <<= 1;
		sec += key;
		key += orig;

        pos  += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size--) {

    }

    sec += key;
    sec += !sec;

    return sec;
}
