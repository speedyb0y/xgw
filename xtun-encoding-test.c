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

#include "encoding.c"

#define CHUNK_SIZE_MAX 1500

static inline uint myrandom (void) {

	static u64 x = 0;

	x += time(NULL);
	x += x;

	return x;
}

int main (void) {

	u8 chunk[CHUNK_SIZE_MAX]; int chunkSize;
	u8 chunkRW[CHUNK_SIZE_MAX];

	while ((chunkSize = read(STDIN_FILENO, chunk, (1 + (myrandom() % (CHUNK_SIZE_MAX - 1)))))) {

		if (chunkSize == -1) {
			fprintf(stderr, "FAILED TO READ: %s\n", strerror(errno));
			return 1;
		}

		// USA ESSE ORIGINAL
		memcpy(chunkRW, chunk, chunkSize);

		const u16 secret = 0;
		const u32 key = 1;

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

	return 0;
}
