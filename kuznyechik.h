/*
 * kuznyechik.h
 *
 * Copyright (C) 2017  Vlasta Vesely
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of General Public License version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Most basic example usage:
 *    struct kuznyechik_subkeys subkeys;
 *    kuznyechik_set_key(&subkeys, key);
 *    kuznyechik_encrypt(&subkeys, ciphertext, plaintext);
 *    kuznyechik_decrypt(&subkeys, plaintext, ciphertext);
 *    kuznyechik_wipe_key(&subkeys);
 *
 * Test vectors (from the reference document):
 *    K = 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
 *    P = 1122334455667700ffeeddccbbaa9988
 *    C = 7f679d90bebc24305a468d42b9d4edcd
 */

#ifndef __KUZNYECHIK_H
#define __KUZNYECHIK_H

#if defined (__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#ifndef ALIGN
#define ALIGN(n)	__attribute__((aligned(n)))
#endif

struct kuznyechik_subkeys {
	uint64_t ek[10][2];
	uint64_t dk[10][2];
};

int kuznyechik_set_key(struct kuznyechik_subkeys *subkeys,
		       const unsigned char *key);

void kuznyechik_encrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in);

void kuznyechik_decrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in);

void kuznyechik_wipe_key(struct kuznyechik_subkeys *subkeys);

#if defined (__cplusplus)
}
#endif

#endif /* __KUZNYECHIK_H */
