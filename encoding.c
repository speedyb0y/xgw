
#define BYTE_X 0x33

static u16 encode (u64 hash, u64 key, u8* pos, u8* const end) {

    while (pos != end) {

        const uint orig = *pos;

        hash <<= 1;
        hash += orig;

        uint value = orig;

        value ^= key;
        value &= 0xFF;
        value |= 0x100;
        value -= BYTE_X;
        value ^= (value & 0xF) << 4;
        value &= 0xFF;

        key <<= 1;
        key += orig;

        *pos++ = value;
    }

    hash += hash >> 32;
    hash += hash >> 16;
    hash &= 0xFFFFU;
    // SE FOR 0, TRANSFORMA EM 1
    hash += !hash;

    return (u16)hash;
}

static u16 decode (u64 hash, u64 key, u8* pos, u8* const end) {

    while (pos != end) {

        uint value = *pos;

        value ^= (value & 0xF) << 4;
        value += BYTE_X;
        value ^= key;
        value &= 0xFF;

        key <<= 1;
        key += value;

        *pos++ = value;

        hash <<= 1;
        hash += value;
    }

    hash += hash >> 32;
    hash += hash >> 16;
    hash &= 0xFFFFU;
    // SE FOR 0, TRANSFORMA EM 1
    hash += !hash;

    return (u16)hash;
}
