/*
 * Kuznyechik / GOST R 34.12-2015
 * National Standard of the Russian Federation
 *
 * Copyright © 2017, 2019, 2025, Vlasta Vesely <vlastavesely@proton.me>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. There is ABSOLUTELY NO WARRANTY, express
 * or implied. / Распространение и использование в исходной и бинарной
 * формах, с изменениями или без них, разрешены. ГАРАНТИЙ АБСОЛЮТНО НЕТ,
 * ни явных, ни подразумеваемых.
 *
 * This code is released under the terms of GPLv2. For more information,
 * see the file COPYING. / Этот код выпущен на условиях GPLv2. Для получения
 * дополнительной информации смотрите файл COPYING (на английском языке).
 */
#ifndef __KUZNYECHIK_H
#define __KUZNYECHIK_H

#include <stdint.h>

#if defined (__cplusplus)
extern "C" {
#endif

struct kuznyechik_subkeys {
	uint64_t ek[20];	/* encryption keys (10 rounds × 2 uint64_t) */
	uint64_t dk[20];	/* decryption keys (10 rounds × 2 uint64_t) */
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
