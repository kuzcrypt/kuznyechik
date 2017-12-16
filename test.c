#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#define BENCH_BUFSIZE 1024 * 1024
#define BENCH_ITER 5

#include "kuznyechik.h"

/*
 * Test vectors are from the reference document.
 */
ALIGN(16) static const unsigned char key[32] = {
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

ALIGN(16) static const unsigned char plaintext[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
};

ALIGN(16) static const unsigned char ciphertext[16] = {
	0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
	0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd
};

static double do_benchmark()
{
	ALIGN(16) struct kuznyechik_subkeys subkeys;
	ALIGN(16) unsigned char buffer[BENCH_BUFSIZE];
	unsigned char *ptr, *eptr;
	clock_t stime;

	ptr = buffer;
	eptr = buffer + sizeof(buffer);

	/* Randomize the buffer */
	while (ptr < eptr)
		*ptr++ = rand();

	ptr = buffer;
	kuznyechik_set_key(&subkeys, key);

	/* Encrypt whole buffer */
	stime = clock();
	while (ptr < eptr) {
		kuznyechik_encrypt(&subkeys, ptr, ptr);
		ptr += 16;
	}

	return (double) (clock() - stime) / CLOCKS_PER_SEC;
}

static void print_block(const unsigned char *blk, const char *prefix)
{
	unsigned int i;

	printf("%s ", prefix);
	for (i = 0; i < 16; i++)
		printf("%02x", blk[i]);
	putchar('\n');
}

int main(int argc, const char **argv)
{
	ALIGN(16) unsigned char buffer[16];
	ALIGN(16) struct kuznyechik_subkeys subkeys;
	double elapsed, mbs;
	unsigned int i;
	int retval = 0;

	srand(time(NULL));

	/* Print test vectors */
	kuznyechik_set_key(&subkeys, key);
	print_block(plaintext, "P:");
	kuznyechik_encrypt(&subkeys, buffer, plaintext);
	print_block(buffer, "C:");
	kuznyechik_decrypt(&subkeys, buffer, buffer);
	print_block(buffer, "P:");

	/* Do benchmark */
	putchar('\n');
	for (i = 0; i < BENCH_ITER; i++) {
		elapsed = do_benchmark();
		mbs = (double) (BENCH_BUFSIZE) / (double) elapsed / 1024 / 1024;
		fprintf(stdout, "[%d/%d] Encryption speed: %f MB/s\n",
			i + 1, BENCH_ITER, mbs);
	}
	putchar('\n');

	return retval;
}
