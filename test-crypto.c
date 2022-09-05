/*

    gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-crypto-test.c -DCHUNK_SIZE_MIN=$[128*1024] -DCHUNK_SIZE_MAX=$[128*1024+512]

    openssl aes-256-cbc -salt -in /dev/zero -out /proc/self/fd/1 -pass stdin <<< $(sha256sum <<< ewewgewew) | pv > /dev/null
*/

#include "config-test-crypto.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define loop while(1)

#define elif else if

typedef unsigned int uint;
typedef unsigned long long int uintll;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#if 0 // TODO: FIXME:
#define BE8(x)  (x)
#define BE16(x) (x)
#define BE32(x) (x)
#define BE64(x) (x)
#else
#define BE8(x)                    ((u8)(x))
#define BE16(x) __builtin_bswap16((u16)(x))
#define BE32(x) __builtin_bswap32((u32)(x))
#define BE64(x) __builtin_bswap64((u64)(x))
#endif

#define CACHE_LINE_SIZE 64

#include "kmod/crypto.c"

#ifndef TEST_CHUNK_SIZE_MIN
#define TEST_CHUNK_SIZE_MIN 128
#endif

#ifndef TEST_CHUNK_SIZE_MAX
#define TEST_CHUNK_SIZE_MAX 1500
#endif

#ifndef TEST_ENCODE
#define TEST_ENCODE 1
#endif

#ifndef TEST_DECODE
#define TEST_DECODE 1
#endif

#ifndef TEST_VERIFY_HASH
#define TEST_VERIFY_HASH 1
#endif

#ifndef TEST_VERIFY_DATA
#define TEST_VERIFY_DATA 1
#endif

#ifndef TEST_PRINT
#define TEST_PRINT 1
#endif

#ifndef TEST_LOOPS
#define TEST_LOOPS 16
#endif

#ifndef TEST_ORIGINAL
#define TEST_ORIGINAL 1
#endif

#ifndef TEST_CRYPTO_ALGO
#define TEST_CRYPTO_ALGO XGW_CRYPTO_ALGO_NULL0
#endif

#ifndef TEST_CRYPTO_PARAMS
#define TEST_CRYPTO_PARAMS 1
#endif

#if TEST_PRINT
#define print(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#define print(...) ({})
#endif

#define err(fmt, ...) ({ fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__); return 1; })

static inline u64 myrandom (void) {

    static u64 x = 0x5564EB5A1465607ULL;

    //x += time(NULL);
    x += 1;

    return x;
}

int main (void) {

    xtun_crypto_algo_e cryptoAlgo;
    xtun_crypto_params_s cryptoKey;

    switch ((cryptoAlgo = TEST_CRYPTO_ALGO)) {
#if      XCONF_XGW_CRYPTO_ALGO_NULL0
        case XGW_CRYPTO_ALGO_NULL0:
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_NULLX
        case XGW_CRYPTO_ALGO_NULLX:
            cryptoKey.nullx.x = 0x1234;
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SUM32
        case XGW_CRYPTO_ALGO_SUM32:
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SUM64
        case XGW_CRYPTO_ALGO_SUM64:
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
        case XGW_CRYPTO_ALGO_SHIFT32_1:
            cryptoKey.shift32_1.k = 0x05547898U;
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
        case XGW_CRYPTO_ALGO_SHIFT64_1:
            cryptoKey.shift64_1.k = 0x464564456ULL;
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
        case XGW_CRYPTO_ALGO_SHIFT64_2:
            cryptoKey.shift64_2.a = 0x464564456ULL;
            cryptoKey.shift64_2.b = 0xE34232045ULL;
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
        case XGW_CRYPTO_ALGO_SHIFT64_3:
            cryptoKey.shift64_3.a = 0x464564456ULL;
            cryptoKey.shift64_3.b = 0xE34232045ULL;
            cryptoKey.shift64_3.c = 0x004560464ULL;
            break;
#endif
#if      XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
        case XGW_CRYPTO_ALGO_SHIFT64_4:
            cryptoKey.shift64_4.a = 0x464564456ULL;
            cryptoKey.shift64_4.b = 0xE34232045ULL;
            cryptoKey.shift64_4.c = 0x004560464ULL;
            cryptoKey.shift64_4.d = 0x352532532ULL;
            break;
#endif
    }

    u8 chunk  [TEST_CHUNK_SIZE_MAX];
    u8 chunkRW[TEST_CHUNK_SIZE_MAX];
    int chunkSize;

    while ((chunkSize = read(STDIN_FILENO, chunk, (TEST_CHUNK_SIZE_MIN + (myrandom() % (TEST_CHUNK_SIZE_MAX - TEST_CHUNK_SIZE_MIN))))) > 0) {

            print("SIZE %u", chunkSize);
#if !TEST_ORIGINAL
            memcpy(chunkRW, chunk, chunkSize);
#endif
        for (uint c = TEST_LOOPS; c; c--) {

#if TEST_ORIGINAL
            memcpy(chunkRW, chunk, chunkSize);
#endif

#if TEST_CRYPTO_PARAMS
			cryptoKey[0] += (u64)myrandom();
			cryptoKey[1] += (u64)myrandom();
			cryptoKey[2] += (u64)myrandom();
			cryptoKey[3] += (u64)myrandom();
#endif

            // ENCODE
#if TEST_ENCODE
            const u16 hashOriginal = xtun_crypto_encode(cryptoAlgo, &cryptoKey, chunkRW, chunkSize);
#else
            const u16 hashOriginal = 0;
#endif
            const int written = write(STDOUT_FILENO, chunkRW, chunkSize);

            if (written == -1)
                err("FAILED TO WRITE: %s", strerror(errno));

            if (written != chunkSize)
                err("FAILED TO WRITE: INCOMPLETE");

            switch (cryptoAlgo) {
#if              XCONF_XGW_CRYPTO_ALGO_NULL0
                case XGW_CRYPTO_ALGO_NULL0:
                    print(" -- HASH 0x%04X", hashOriginal);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_NULLX
                case XGW_CRYPTO_ALGO_NULLX:
                    print(" -- HASH 0x%04X KEYS 0x%016llX", hashOriginal,
                        (uintll)cryptoKey.nullx.x);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SUM32
                case XGW_CRYPTO_ALGO_SUM32:
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SUM64
                case XGW_CRYPTO_ALGO_SUM64:
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SHIFT32_1
                case XGW_CRYPTO_ALGO_SHIFT32_1:
                    print(" -- HASH 0x%04X KEYS 0x%08llX", hashOriginal,
                        (uintll)cryptoKey.shift32_1.k);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SHIFT64_1
                case XGW_CRYPTO_ALGO_SHIFT64_1:
                    print(" -- HASH 0x%04X KEYS 0x%016llX", hashOriginal,
                        (uintll)cryptoKey.shift64_1.k);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SHIFT64_2
                case XGW_CRYPTO_ALGO_SHIFT64_2:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoKey.shift64_2.a,
                        (uintll)cryptoKey.shift64_2.b);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SHIFT64_3
                case XGW_CRYPTO_ALGO_SHIFT64_3:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoKey.shift64_3.a,
                        (uintll)cryptoKey.shift64_3.b,
                        (uintll)cryptoKey.shift64_3.c);
                    break;
#endif
#if              XCONF_XGW_CRYPTO_ALGO_SHIFT64_4
                case XGW_CRYPTO_ALGO_SHIFT64_4:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoKey.shift64_4.a,
                        (uintll)cryptoKey.shift64_4.b,
                        (uintll)cryptoKey.shift64_4.c,
                        (uintll)cryptoKey.shift64_4.d);
                    break;
#endif
            }

#if TEST_DECODE
            const u64 hashNew = xtun_crypto_decode(cryptoAlgo, &cryptoKey, chunkRW, chunkSize);
#if TEST_VERIFY_DATA
            if (memcmp(chunk, chunkRW, chunkSize))
                err("DATA MISMATCH");
#endif
#if TEST_VERIFY_HASH
            if (hashNew != hashOriginal)
                err("HASH MISMATCH");
#endif
#endif
        }
    }

    if (chunkSize == -1)
        err("FAILED TO READ: %s", strerror(errno));

    return 0;
}
