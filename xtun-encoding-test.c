/*

*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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

#define BUFF_SIZE 65536

int main (int argsN, const char* args[]) {

	int enc;

	if (argsN != 2) {

		return 1;
	}

	if (!strcmp(args[1], "e") ||
		!strcmp(args[1], "enc") ||
		!strcmp(args[1], "encode") ||
		!strcmp(args[1], "encrypt")) {
		enc = 1;
	} elif (
		!strcmp(args[1], "d") ||
		!strcmp(args[1], "dec") ||
		!strcmp(args[1], "decode") ||
		!strcmp(args[1], "decrypt")) {
		enc = 0;
	} else {
		
		return 1;
	}

	void* const buff = malloc(BUFF_SIZE);

	if (buff == NULL) {

		return 1;
	}

	u64 accum = ZERO;

	loop {

		const int readen = read(STDIN_FILENO, buff, BUFF_SIZE);

		if (readen == 0) {
			//fprintf(stderr, "EOF\n");
			return 0;
		}

		if (readen == -1) {
			fprintf(stderr, "FAILED TO READ: %s\n", strerror(errno));
			return 1;
		}

		u8* pos = buff;
		u8* end = buff + readen;

		while (pos != end) {
			
			uint value = *pos;

			if (enc) {
				// ENCODE

				const uint orig = value;

				value ^= accum;
				value &= 0xFF;
				value |= 0x100;
				value -= BYTE_X;
				value ^= (value & 0xF) << 4;
				value &= 0xFF;

				accum <<= 1;
				accum += orig;
				
			} else {
				// DECODE

				value ^= (value & 0xF) << 4;
				value += BYTE_X;
				value ^= accum;
				value &= 0xFF;
				
				accum <<= 1;
				accum += value;
			}
		
			*pos++ = value;
		}

		const int written = write(STDOUT_FILENO, buff, readen);

		if (written != readen) {
			if (written == -1)
				fprintf(stderr, "FAILED TO READ: %s\n", strerror(errno));
			else
				fprintf(stderr, "FAILED TO WRITE: INCOMPLETE\n");
			return 1;
		}
	}
}
