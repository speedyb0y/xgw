/*

    gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-encoding-test.c -DCHUNK_SIZE_MIN=$[128*1024] -DCHUNK_SIZE_MAX=$[128*1024+512]


    gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-encoding-test.c -DCHUNK_SIZE_MIN=$[128*1024] -DCHUNK_SIZE_MAX=$[128*1024+512] -DDECODE=0 -DPRINT=0

    ./a.out < /dev/zero | pv > /dev/null
    openssl aes-256-cbc -salt -in /dev/zero -out /proc/self/fd/1 -pass stdin <<< $(sha256sum <<< ewewgewew) | pv > /dev/null
*/

#include "config.h"

#ifndef TEST
#define TEST 0
#endif

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

#define BE8(x) (x)
#define BE64(x)(x) // TODO: FIXME:

#define CACHE_LINE_SIZE 64

#include "xtun-crypto.c"

#ifndef CHUNK_SIZE_MIN
#define CHUNK_SIZE_MIN 128
#endif

#ifndef CHUNK_SIZE_MAX
#define CHUNK_SIZE_MAX 1500
#endif

#ifndef TEST_ENCODE
#define TEST_ENCODE 1
#endif

#ifndef TEST_DECODE
#define TEST_DECODE 1
#endif

#ifndef PRINT
#define PRINT 1
#endif

#ifndef COUNT
#define COUNT 1
#endif

#ifndef TEST_SPEED
#define TEST_SPEED 0
#endif

#ifndef TEST_CRYPTO_ALGO_NULL0
#define TEST_CRYPTO_ALGO_NULL0 0
#endif
#ifndef TEST_CRYPTO_ALGO_NULLX
#define TEST_CRYPTO_ALGO_NULLX 0
#endif
#ifndef TEST_CRYPTO_ALGO_SUM32
#define TEST_CRYPTO_ALGO_SUM32 0
#endif
#ifndef TEST_CRYPTO_ALGO_SUM64
#define TEST_CRYPTO_ALGO_SUM64 0
#endif
#ifndef TEST_CRYPTO_ALGO_SHIFT64_1
#define TEST_CRYPTO_ALGO_SHIFT64_1 0
#endif
#ifndef TEST_CRYPTO_ALGO_SHIFT64_2
#define TEST_CRYPTO_ALGO_SHIFT64_2 0
#endif
#ifndef TEST_CRYPTO_ALGO_SHIFT64_3
#define TEST_CRYPTO_ALGO_SHIFT64_3 0
#endif
#ifndef TEST_CRYPTO_ALGO_SHIFT64_4
#define TEST_CRYPTO_ALGO_SHIFT64_4 0
#endif

static inline u64 myrandom (void) {

    static u64 x = 0x5564EB5A1465607ULL;

    //x += time(NULL);
    x += 1;

    return x;
}

static const xtun_crypto_algo_e cryptoAlgo = XTUN_CRYPTO_ALGO;

static xtun_crypto_params_s cryptoParams = {
#if   TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_NULL0

#elif TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_NULLX
    .nullx = {
        .x = 0x1234,
    }
#elif TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_SHIFT64_4
    .shift64_4 = {
        .k = {
            0x464564456ULL,
            0xE34232045ULL,
            0x004560464ULL,
            0x352532532ULL,
        }
    }
#else
#error
#endif
};

int main (void) {

    u8 chunk[CHUNK_SIZE_MAX];
    u8 chunkRW[CHUNK_SIZE_MAX];
    int chunkSize;

    while ((chunkSize = read(STDIN_FILENO, chunk, (CHUNK_SIZE_MIN + (myrandom() % (CHUNK_SIZE_MAX - CHUNK_SIZE_MIN))))) > 0) {

#if PRINT
        fprintf(stderr, "SIZE %u\n", chunkSize);
#endif
#if TEST_SPEED
            // USA ESSE ORIGINAL
            memcpy(chunkRW, chunk, chunkSize);
#endif
        for (uint c = COUNT; c; c--) {

#if !TEST_SPEED
            memcpy(chunkRW, chunk, chunkSize);
#endif

#if   TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_NULL0
			// NOTHING
#elif TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_NULLX
            cryptoParams.nullx.x++;
#elif TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_SHIFT64_3
            cryptoParams.shift64_3.keys[0] += (u64)myrandom();
            cryptoParams.shift64_3.keys[1] += (u64)myrandom();
            cryptoParams.shift64_3.keys[2] += (u64)myrandom();
#elif TEST_CRYPTO_ALGO == XTUN_CRYPTO_ALGO_SHIFT64_4
            cryptoParams.shift64_4.keys[0] += (u64)myrandom();
            cryptoParams.shift64_4.keys[1] += (u64)myrandom();
            cryptoParams.shift64_4.keys[2] += (u64)myrandom();
            cryptoParams.shift64_4.keys[3] += (u64)myrandom();
#endif

            // ENCODE
#if TEST_ENCODE
            const u16 hashOriginal = xtun_crypto_encode[cryptoAlgo](&cryptoParams, chunkRW, chunkSize);
#else
            const u16 hashOriginal = 0;
#endif
            // MOSTRA COMO FICA ENCODADO
            const int written = write(STDOUT_FILENO, chunkRW, chunkSize);

            if (written == -1) {
                fprintf(stderr, "FAILED TO WRITE: %s\n", strerror(errno));
                return 1;
            }

            if (written != chunkSize) {
                fprintf(stderr, "FAILED TO WRITE: INCOMPLETE\n");
                return 1;
            }

#if PRINT
            fprintf(stderr, "\n -- KEYS 0x%016llX 0x%016llX 0x%016llX 0x%016llX  = HASH 0x%04X \n",
                (uintll)cryptoParams.shift64_4.keys[0],
                (uintll)cryptoParams.shift64_4.keys[1],
                (uintll)cryptoParams.shift64_4.keys[2],
                (uintll)cryptoParams.shift64_4.keys[3],
                hashOriginal);
#endif
#if TEST_DECODE
            // DECODE
#if !TEST
            const u64 hashNew = xtun_crypto_decode[cryptoAlgo](&cryptoParams, keys, chunkRW, chunkSize);
#else
            const u64 hashNew = hashOriginal;
#endif

            // COMPARE DATA
            if (memcmp(chunk, chunkRW, chunkSize)) {
                fprintf(stderr, "ERROR: DATA MISMATCH\n");
                return 1;
            }

            // COMPARE HASH
            if (hashNew != hashOriginal) {
                fprintf(stderr, "ERROR: HASH MISMATCH\n");
                return 1;
            }
#endif
        }
    }

    if (chunkSize == -1) {
        fprintf(stderr, "FAILED TO READ: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
