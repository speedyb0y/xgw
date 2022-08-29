
#if XGW_XTUN_ENCODING_BYTE_X <= 0
 || XGW_XTUN_ENCODING_BYTE_X >= 0xFF
#error "BAD BYTE X"
#endif

#define BYTE_X XGW_XTUN_ENCODING_BYTE_X

#define ENCODE_SECRET_ADD XGW_XTUN_ENCODE_SECRET_ADD

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u16 encode (u64 secret, u64 key, u8* pos, u8* const end) {

    while (pos != end) {

        const uint orig = *pos;

        uint value = orig;

        value ^= key;
        value &= 0xFF;
        value |= 0x100;
        value -= BYTE_X;
        value ^= (value & 0xF) << 4;
        value &= 0xFF;

        key += orig << (secret % 16);

        *pos++ = value;

        secret += orig   << (secret % 32);
        secret += secret << (orig  % 32);
        secret += ENCODE_SECRET_ADD;
    }

    secret += key;
    secret += secret >> 32;
    secret += secret >> 16;
    secret &= 0xFFFFU;
    // SE FOR 0, TRANSFORMA EM 1
    secret += !secret;

    return (u16)secret;
}

// RETORNA: HASH OF SECRET + KEY + ORIGINAL
static u16 decode (u64 secret, u64 key, u8* pos, u8* const end) {

    while (pos != end) {

        uint value = *pos;

        value ^= (value & 0xF) << 4;
        value += BYTE_X;
        value ^= key;
        value &= 0xFF;

        key += value << (secret % 16);

        *pos++ = value;

		secret += value  << (secret % 32);
        secret += secret << (value  % 32);
        secret += ENCODE_SECRET_ADD;
    }

    secret += key;
    secret += secret >> 32;
    secret += secret >> 16;
    secret &= 0xFFFFU;
    // SE FOR 0, TRANSFORMA EM 1
    secret += !secret;

    return (u16)secret;
}
