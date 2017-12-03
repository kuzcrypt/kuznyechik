#ifndef __KUZNYECHIK_H
#define __KUZNYECHIK_H

#include <stdint.h>

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