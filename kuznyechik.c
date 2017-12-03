#include <string.h>

#include "kuznyechik.h"

int kuznyechik_set_key(struct kuznyechik_subkeys *subkeys,
		       const unsigned char *key)
{

	return 0;
}

void kuznyechik_encrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in)
{
}

void kuznyechik_decrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in)
{
}

void kuznyechik_wipe_key(struct kuznyechik_subkeys *subkeys)
{
	memset(subkeys, 0, sizeof(struct kuznyechik_subkeys));
}
