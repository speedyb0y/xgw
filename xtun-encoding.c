
#define XTUN_KEYS_N XGW_XTUN_KEYS_N

#define XTUN_ENCODING_A_ADD XGW_XTUN_ENCODING_A_ADD
#define XTUN_ENCODING_B_ADD XGW_XTUN_ENCODING_B_ADD
#define XTUN_ENCODING_C_ADD XGW_XTUN_ENCODING_C_ADD
#define XTUN_ENCODING_D_ADD XGW_XTUN_ENCODING_D_ADD

#if XTUN_ENCODING_A_ADD <= 0 \
 || XTUN_ENCODING_A_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_ENCODING_A_ADD"
#endif

#if XTUN_ENCODING_B_ADD <= 0 \
 || XTUN_ENCODING_B_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_ENCODING_B_ADD"
#endif

#if XTUN_ENCODING_C_ADD <= 0 \
 || XTUN_ENCODING_C_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_ENCODING_C_ADD"
#endif

#if XTUN_ENCODING_D_ADD <= 0 \
 || XTUN_ENCODING_D_ADD > 0xFFFFFFFFFFFFFFFF
#error "BAD XTUN_ENCODING_D_ADD"
#endif

#if XTUN_KEYS_N != 4
#error "BAD XTUN_KEYS_N"
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
static u16 xtun_encode_64_4 (const u64 keys[4], void* data, uint size) {

	u64 a = keys[0] + XTUN_ENCODING_A_ADD;
	u64 b = keys[1] + XTUN_ENCODING_B_ADD;
	u64 c = keys[2] + XTUN_ENCODING_C_ADD;
	u64 d = keys[3] + XTUN_ENCODING_D_ADD;
	
	a += encrypt64(d, size);
	b += encrypt64(c, size);
	c += encrypt64(b, size);
	d += encrypt64(a, size);

	data += size;

	while (size >= sizeof(u64)) {
	 
		size -= sizeof(u64);
		data -= sizeof(u64);

		const u64 orig = BE64(*(u64*)data);

		u64 value = orig;

		value = encrypt64(value, size);
		value = encrypt64(value, a);
		value = encrypt64(value, b);
		value = encrypt64(value, c);
		value = encrypt64(value, d);

		*(u64*)data = BE64(value);

		a += encrypt64(d, orig);
		b += encrypt64(a, size);		
		c += encrypt64(orig, b);
		d += encrypt64(orig, c);
	}

	while (size) {
	 
		size -= sizeof(u8);
		data -= sizeof(u8);

		const u8 orig = BE8(*(u8*)data);

		u64 value = orig;

		value += encrypt64(a, size);
		value += encrypt64(b, size);
		value += encrypt64(c, size);
		value += encrypt64(d, size);
		value &= 0xFFU;

		*(u8*)data = BE8(value);

		a += encrypt64(b, orig);
		b += encrypt64(orig, a);
	}

	a += b;
	a += a >> 32;
	a += a >> 16;
	a &= 0xFFFFULL;
	
    return (u16)a;
}

// RETORNA: HASH OF SECRET + KEY + SIZE + ORIGINAL
static u16 xtun_decode_64_4 (const u64 keys[XTUN_KEYS_N], void* data, uint size) {

	u64 a = keys[0] + XTUN_ENCODING_A_ADD;
	u64 b = keys[1] + XTUN_ENCODING_B_ADD;
	u64 c = keys[2] + XTUN_ENCODING_C_ADD;
	u64 d = keys[3] + XTUN_ENCODING_D_ADD;
	
	a += encrypt64(d, size);
	b += encrypt64(c, size);
	c += encrypt64(b, size);
	d += encrypt64(a, size);

	data += size;

	while (size >= sizeof(u64)) {

		size -= sizeof(u64);
		data -= sizeof(u64);

		u64 orig = BE64(*(u64*)data);

		orig = decrypt64(orig, d);
		orig = decrypt64(orig, c);
		orig = decrypt64(orig, b);
		orig = decrypt64(orig, a);
		orig = decrypt64(orig, size);

		*(u64*)data = BE64(orig);

		a += encrypt64(d, orig);
		b += encrypt64(a, size);		
		c += encrypt64(orig, b);
		d += encrypt64(orig, c);
	}

	while (size) {

		size -= sizeof(u8);
		data -= sizeof(u8);

		u64 orig = BE8(*(u8*)data);

		orig -= encrypt64(d, size);
		orig -= encrypt64(c, size);
		orig -= encrypt64(b, size);
		orig -= encrypt64(a, size);
		orig &= 0xFFU;

		*(u8*)data = BE8(orig);

		a += encrypt64(b, orig);
		b += encrypt64(orig, a);
	}

	a += b;
	a += a >> 32;
	a += a >> 16;
	a &= 0xFFFFULL;

    return (u16)a;
}

static u16 xtun_encode_0 (const void* const restrict keys, void* restrict data, uint size) {

    (void)keys;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_decode_0 (const void* const restrict keys, void* restrict data, uint size) {

    (void)keys;
    (void)data;
    (void)size;

    return (u16)0;
}

static u16 xtun_encode_x (const void* const restrict hash, void* restrict data, uint size) {

    (void)data;
    (void)size;

    return *hash;
}

static u16 xtun_decode_x (const void* const restrict hash, void* restrict data, uint size) {

    (void)data;
    (void)size;

    return *hash;
}
