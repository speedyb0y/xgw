/*

*/

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

#define CHUNK_SIZE_MAX 1500

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

	while ((chunkSize = read(STDIN_FILENO, chunk, (1 + (myrandom() % (CHUNK_SIZE_MAX - 1))))) > 0) {

		fprintf(stderr, "SIZE %u\n", chunkSize);

		for (uint c = 16; c; c--) {
			
			// USA ESSE ORIGINAL
			memcpy(chunkRW, chunk, chunkSize);

			const u16 secret = (u16)myrandom();
			const u32 key    = (u32)myrandom(); // FIXME: NAO PODE SER 0

			// ENCODE		
			const u16 hashOriginal = encode(secret, key, chunkRW, chunkRW + chunkSize);

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

			fprintf(stderr, "\n -- SECRET %0llX KEY 0x%08X = HASH 0x%04X \n",
				(unsigned long long int )secret, key, hashOriginal);

			// DECODE
			const u16 hashNew = decode(secret, key, chunkRW, chunkRW + chunkSize);

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
		}
	}

	if (chunkSize == -1) {
		fprintf(stderr, "FAILED TO READ: %s\n", strerror(errno));
		return 1;
	}

	return 0;
}
