
#define XTUN_ENCODING_ORIG_ADD XGW_XTUN_ENCODING_BYTE_X

#define ENCODE_SECRET_ADD XGW_XTUN_ENCODE_SECRET_ADD

#if XTUN_ENCODING_ORIG_ADD <= 0 \
 || XTUN_ENCODING_ORIG_ADD >= 0xFFFFFFFFFFFFFFFF
#error "BAD ORIG ADD"
#endif

#if ENCODE_SECRET_ADD <= 0 \
 || ENCODE_SECRET_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD SECRET ADD"
#endif

#define BE64(x)(x) // TODO: FIXME:


#define ENCODE_INIT_KEY_ADD		0x565640460654ULL
#define ENCODE_INIT_SEC_ADD		0x505010A60654ULL
#define ENCODE_ROUND_KEY_ADD		0x563343EF0654ULL
#define ENCODE_ROUND_SEC_ADD		0x56564B295654ULL

// PEGA UM MENOR E TRANSFORMA EM UM MAIOR
static inline u64 SECRET16 (u64 sec) {

	sec |= sec << 16;
	sec |= sec << 32;

	return sec;
}

static inline u64 KEY16 (u64 key) {

	key |= key << 16;
	key |= key << 32;

	return key;
}

static inline u64 swap (const u64 x, const uint q) {

	const u64 a = x & ((1ULL << q) - 1ULL);
	const u64 b = x >> q;
	
	return (a << (64 - q)) | b;
}

static inline u64 unswap (const u64 x, uint q) {

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

    key += ENCODE_INIT_KEY_ADD;
    key += sec << (size % 32);

    return key;
}

static inline u64 xtun_encoding_init_sec (u64 sec, u64 key, uint size) {

    sec += ENCODE_INIT_SEC_ADD;
    sec += key << (size % 32);

    return sec;
}

static inline u64 xtun_encoding_round_key (u64 sec, u64 key, uint size, u8 orig) {

    key += ENCODE_ROUND_KEY_ADD;
    key += sec << (orig % 32);

    return key;
}

static inline u64 xtun_encoding_round_sec (u64 sec, u64 key, uint size, u8 orig) {

    sec += ENCODE_ROUND_SEC_ADD;
    sec += key << ((orig + size) % 32);

    return sec;
}

static inline u64 xtun_encoding_finish_hash (u64 sec, u64 key) {

    sec ^= key;
    // SE FOR 0, TRANSFORMA EM 1
    sec += !sec;

    return sec;
}

#define Q(sec, key, size) ((sec + key + size) % 64)

static inline u64 e (u64 sec, u64 key, uint size, u64 x) {
	
	x += XTUN_ENCODING_ORIG_ADD;
	x = swap(x, Q(sec, key, size));
	
	return x;
}

static inline u64 d (u64 sec, u64 key, uint size, u64 x) {

	x = unswap(x, Q(sec, key, size));
	x -= XTUN_ENCODING_ORIG_ADD;
	
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
