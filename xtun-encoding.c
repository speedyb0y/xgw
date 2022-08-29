
#define XTUN_ENCODING_ORIG_ADD XGW_XTUN_ENCODING_BYTE_X

#define ENCODE_SECRET_ADD XGW_XTUN_ENCODE_SECRET_ADD

#if XTUN_ENCODING_ORIG_ADD <= 0 \
 || XTUN_ENCODING_ORIG_ADD >= 0xFF
#error "BAD ORIG ADD"
#endif

#if ENCODE_SECRET_ADD <= 0 \
 || ENCODE_SECRET_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD SECRET ADD"
#endif

// U64 -> U16 ; 0 -> 1
static inline u16 xtun_encoding_hash16 (u64 hash) {
    
    hash += hash >> 32;
    hash += hash >> 16;
    hash &= 0xFFFFU;

    return (u16)hash;
}

static inline u64 xtun_encoding_init_key (u64 sec, u64 key) {

    key += 0x34342;
    key += sec << (key % 32);

    return key;
}

static inline u64 xtun_encoding_init_sec (u64 sec, u64 key) {

    sec += 0x3432;
    sec += key;

    return sec;
}

static inline u64 xtun_encoding_round_key (u64 sec, u64 key, u8 orig) {

    key += orig << (sec % 16);

    return key;
}

static inline u64 xtun_encoding_round_sec (u64 sec, u64 key, u8 orig) {

    sec += orig   << (sec % 32);
    sec += sec << (orig  % 32);
    sec += ENCODE_SECRET_ADD;

    return sec;
}

static inline u64 xtun_encoding_finish_hash (sec, key) {

    // SE FOR 0, TRANSFORMA EM 1
    sec += !sec;
    
    return sec;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, u8* pos, u8* const end) {

    sec = xtun_encoding_init_sec(sec, key);
    key = xtun_encoding_init_key(sec, key);

    while (pos != end) {

        const uint orig = *pos;

        uint value = orig;

        value ^= key;
        value &= 0xFF;
        value |= 0x100;
        value -= XTUN_ENCODING_ORIG_ADD;
        value ^= (value & 0xF) << 4;
        value &= 0xFF;

        *pos++ = value;

        sec = xtun_encoding_round_sec(sec, key, value);
        key = xtun_encoding_round_key(sec, key, value);
    }

    return xtun_encoding_finish_hash(sec, key);
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_decode (u64 sec, u64 key, u8* pos, u8* const end) {

    sec = xtun_encoding_init_sec(sec, key);
    key = xtun_encoding_init_key(sec, key);

    while (pos != end) {

        uint value = *pos;

        value ^= (value & 0xF) << 4;
        value += XTUN_ENCODING_ORIG_ADD;
        value ^= key;
        value &= 0xFF;

        *pos++ = value;

        sec = xtun_encoding_round_sec(sec, key, value);
        key = xtun_encoding_round_key(sec, key, value);
    }

    return xtun_encoding_finish_hash(sec, key);
}
