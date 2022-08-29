
#if XGW_XTUN_ENCODING_BYTE_X <= 0
 || XGW_XTUN_ENCODING_BYTE_X >= 0xFF
#error "BAD BYTE X"
#endif

#define BYTE_X XGW_XTUN_ENCODING_BYTE_X

#define ENCODE_SECRET_ADD XGW_XTUN_ENCODE_SECRET_ADD

// U64 -> U16 ; 0 -> 1
static inline u16 hash64_16_01 (u64 hash) {
    
    hash += hash >> 32;
    hash += hash >> 16;
    hash &= 0xFFFFU;
    // SE FOR 0, TRANSFORMA EM 1
    hash += !hash;

    return (u16)hash;
}

static inline u64 xtun_encoding_key_init (u64 sec, u64 key) {

    key += 0x34342;
    key += sec << (key % 32);

    return key;
}

static inline u64 xtun_encoding_sec_init (u64 sec, u64 key) {

    sec += 0x3432;
    sec += key;

    return sec;
}

static inline u64 xtun_encoding_key_round (u64 sec, u64 key, u8 orig) {

    key += orig << (sec % 16);

    return key;
}

static inline u64 xtun_encoding_sec_round (u64 sec, u64 key, u8 orig) {

    sec += orig   << (sec % 32);
    sec += sec << (orig  % 32);
    sec += ENCODE_SECRET_ADD;

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_encode (u64 sec, u64 key, u8* pos, u8* const end) {

    sec = xtun_encoding_sec_init(sec, key);
    key = xtun_encoding_key_init(sec, key);

    while (pos != end) {

        const uint orig = *pos;

        uint value = orig;

        value ^= key;
        value &= 0xFF;
        value |= 0x100;
        value -= BYTE_X;
        value ^= (value & 0xF) << 4;
        value &= 0xFF;

        *pos++ = value;

        sec = xtun_encoding_sec_round(sec, key, value);
        key = xtun_encoding_key_round(sec, key, value);
    }

    return sec;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u64 xtun_decode (u64 sec, u64 key, u8* pos, u8* const end) {

    sec = xtun_encoding_sec_init(sec, key);
    key = xtun_encoding_key_init(sec, key);

    while (pos != end) {

        uint value = *pos;

        value ^= (value & 0xF) << 4;
        value += BYTE_X;
        value ^= key;
        value &= 0xFF;

        *pos++ = value;

        sec = xtun_encoding_sec_round(sec, key, value);
        key = xtun_encoding_key_round(sec, key, value);
    }

    return sec;
}
