/*

	gcc -fwhole-program -Wall -Wextra -O2 -march=native xtun-encoding-test.c -DCHUNK_SIZE_MIN=$[128*1024] -DCHUNK_SIZE_MAX=$[128*1024+512]
	openssl aes-256-cbc -salt -in /dev/zero -out /proc/self/fd/1 -pass stdin <<< $(sha256sum <<< ewewgewew) | pv > /dev/null
*/

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

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#include "config.h"

#include "xtun-encoding.c"

#ifndef CHUNK_SIZE_MIN
#define  CHUNK_SIZE_MIN 128
#endif

#ifndef CHUNK_SIZE_MAX
#define  CHUNK_SIZE_MAX 1500
#endif

#ifndef DECODE
#define  DECODE 1
#endif

static inline u64 myrandom (void) {

	static u64 x = 0x556465607ULL;

	//x += time(NULL);
	x += 1;

	return x;
}

int main (void) {

	u8 chunk[CHUNK_SIZE_MAX];
	u8 chunkRW[CHUNK_SIZE_MAX];
	int chunkSize;

	while ((chunkSize = read(STDIN_FILENO, chunk, (CHUNK_SIZE_MIN + (myrandom() % (CHUNK_SIZE_MAX - CHUNK_SIZE_MIN))))) > 0) {

		fprintf(stderr, "SIZE %u\n", chunkSize);

		for (uint c = 16; c; c--) {
			
			// USA ESSE ORIGINAL
			memcpy(chunkRW, chunk, chunkSize);

			const u16 secret = (u16)myrandom();
			const u16 key    = (u16)myrandom(); // FIXME: NAO PODE SER 0

			// ENCODE		
#if !TEST
			const u16 hashOriginal = xtun_encode(SECRET16(secret), KEY16(key), chunkRW, chunkSize);
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

			fprintf(stderr, "\n -- SECRET 0x%04X KEY 0x%04X = HASH 0x%04X \n",
				secret, key, hashOriginal);
#if DECODE
			// DECODE
#if !TEST			
			const u16 hashNew = xtun_decode(SECRET16(secret), KEY16(key), chunkRW, chunkSize);
#else
			const u16 hashNew = hashOriginal;
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
