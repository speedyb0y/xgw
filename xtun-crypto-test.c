/*

    gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-crypto-test.c -DCHUNK_SIZE_MIN=$[128*1024] -DCHUNK_SIZE_MAX=$[128*1024+512]

    openssl aes-256-cbc -salt -in /dev/zero -out /proc/self/fd/1 -pass stdin <<< $(sha256sum <<< ewewgewew) | pv > /dev/null
*/

#include "config.h"

#undef XGW_XTUN_CRYPTO_ALGO_NULL0
#undef XGW_XTUN_CRYPTO_ALGO_NULLX
#undef XGW_XTUN_CRYPTO_ALGO_SUM32
#undef XGW_XTUN_CRYPTO_ALGO_SUM64
#undef XGW_XTUN_CRYPTO_ALGO_SHIFT32_1
#undef XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
#undef XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
#undef XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
#undef XGW_XTUN_CRYPTO_ALGO_SHIFT64_4

#define XGW_XTUN_CRYPTO_ALGO_NULL0 1
#define XGW_XTUN_CRYPTO_ALGO_NULLX 1
#define XGW_XTUN_CRYPTO_ALGO_SUM32 1
#define XGW_XTUN_CRYPTO_ALGO_SUM64 1
#define XGW_XTUN_CRYPTO_ALGO_SHIFT32_1 1
#define XGW_XTUN_CRYPTO_ALGO_SHIFT64_1 1
#define XGW_XTUN_CRYPTO_ALGO_SHIFT64_2 0
#define XGW_XTUN_CRYPTO_ALGO_SHIFT64_3 0
#define XGW_XTUN_CRYPTO_ALGO_SHIFT64_4 1

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

#include "xtun-crypto.c"

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
#define TEST_CRYPTO_ALGO XTUN_CRYPTO_ALGO_NULL0
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
    xtun_crypto_params_s cryptoParams;

    switch ((cryptoAlgo = TEST_CRYPTO_ALGO)) {
#if      XGW_XTUN_CRYPTO_ALGO_NULL0
        case XTUN_CRYPTO_ALGO_NULL0:
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_NULLX
        case XTUN_CRYPTO_ALGO_NULLX:
            cryptoParams.nullx.x = 0x1234;
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SUM32
        case XTUN_CRYPTO_ALGO_SUM32:
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SUM64
        case XTUN_CRYPTO_ALGO_SUM64:
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
        case XTUN_CRYPTO_ALGO_SHIFT64_1:
            cryptoParams.shift64_1.k[0] = 0x464564456ULL;
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
        case XTUN_CRYPTO_ALGO_SHIFT64_2:
            cryptoParams.shift64_2.k[0] = 0x464564456ULL;
            cryptoParams.shift64_2.k[1] = 0xE34232045ULL;
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
        case XTUN_CRYPTO_ALGO_SHIFT64_3:
            cryptoParams.shift64_3.k[0] = 0x464564456ULL;
            cryptoParams.shift64_3.k[1] = 0xE34232045ULL;
            cryptoParams.shift64_3.k[2] = 0x004560464ULL;
            break;
#endif
#if      XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
        case XTUN_CRYPTO_ALGO_SHIFT64_4:
            cryptoParams.shift64_4.k[0] = 0x464564456ULL;
            cryptoParams.shift64_4.k[1] = 0xE34232045ULL;
            cryptoParams.shift64_4.k[2] = 0x004560464ULL;
            cryptoParams.shift64_4.k[3] = 0x352532532ULL;
            break;
#endif
        default:
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
            switch (cryptoAlgo) {
#if              XGW_XTUN_CRYPTO_ALGO_NULL0
                case XTUN_CRYPTO_ALGO_NULL0:
                    // NOTHING
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_NULLX
                case XTUN_CRYPTO_ALGO_NULLX:
                    cryptoParams.nullx.x++;
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SUM32
                case XTUN_CRYPTO_ALGO_SUM32:

                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SUM64
                case XTUN_CRYPTO_ALGO_SUM64:

                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
                case XTUN_CRYPTO_ALGO_SHIFT64_1:
                    cryptoParams.shift64_1.k[0] += (u64)myrandom();
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
                case XTUN_CRYPTO_ALGO_SHIFT64_2:
                    cryptoParams.shift64_2.k[0] += (u64)myrandom();
                    cryptoParams.shift64_2.k[1] += (u64)myrandom();
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
                case XTUN_CRYPTO_ALGO_SHIFT64_3:
                    cryptoParams.shift64_3.k[0] += (u64)myrandom();
                    cryptoParams.shift64_3.k[1] += (u64)myrandom();
                    cryptoParams.shift64_3.k[2] += (u64)myrandom();
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
                case XTUN_CRYPTO_ALGO_SHIFT64_4:
                    cryptoParams.shift64_4.k[0] += (u64)myrandom();
                    cryptoParams.shift64_4.k[1] += (u64)myrandom();
                    cryptoParams.shift64_4.k[2] += (u64)myrandom();
                    cryptoParams.shift64_4.k[3] += (u64)myrandom();
                    break;
#endif
                default:
            }
#endif

            // ENCODE
#if TEST_ENCODE
            const u16 hashOriginal = xtun_crypto_encode(cryptoAlgo, &cryptoParams, chunkRW, chunkSize);
#else
            const u16 hashOriginal = 0;
#endif
            const int written = write(STDOUT_FILENO, chunkRW, chunkSize);

            if (written == -1)
                err("FAILED TO WRITE: %s", strerror(errno));

            if (written != chunkSize)
                err("FAILED TO WRITE: INCOMPLETE");

            switch (cryptoAlgo) {
#if              XGW_XTUN_CRYPTO_ALGO_NULL0
                case XTUN_CRYPTO_ALGO_NULL0:
                    print(" -- HASH 0x%04X", hashOriginal);
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_NULLX
                case XTUN_CRYPTO_ALGO_NULLX:
                    print(" -- HASH 0x%04X KEYS 0x%016llX", hashOriginal,
                        (uintll)cryptoParams.nullx.x);
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SUM32
                case XTUN_CRYPTO_ALGO_SUM32:
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SUM64
                case XTUN_CRYPTO_ALGO_SUM64:
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_1
                case XTUN_CRYPTO_ALGO_SHIFT64_1:
                    print(" -- HASH 0x%04X KEYS 0x%016llX", hashOriginal,
                        (uintll)cryptoParams.shift64_4.k[0]);
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_2
                case XTUN_CRYPTO_ALGO_SHIFT64_2:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoParams.shift64_2.k[0],
                        (uintll)cryptoParams.shift64_2.k[1]);
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_3
                case XTUN_CRYPTO_ALGO_SHIFT64_3:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoParams.shift64_3.k[0],
                        (uintll)cryptoParams.shift64_3.k[1],
                        (uintll)cryptoParams.shift64_3.k[2]);
                    break;
#endif
#if              XGW_XTUN_CRYPTO_ALGO_SHIFT64_4
                case XTUN_CRYPTO_ALGO_SHIFT64_4:
                    print(" -- HASH 0x%04X KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX", hashOriginal,
                        (uintll)cryptoParams.shift64_4.k[0],
                        (uintll)cryptoParams.shift64_4.k[1],
                        (uintll)cryptoParams.shift64_4.k[2],
                        (uintll)cryptoParams.shift64_4.k[3]);
                    break;
#endif
                default:
            }

#if TEST_DECODE
            const u64 hashNew = xtun_crypto_decode(cryptoAlgo, &cryptoParams, chunkRW, chunkSize);
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
