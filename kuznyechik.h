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

#ifndef __KUZNYECHIK_H
#define __KUZNYECHIK_H

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

#endif /* __KUZNYECHIK_H */
