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

/*
 * This is an implementation of Kuznyechik, the 128-bit block cipher used as
 * a national standard of the Russian Federation and described in ГОСТ Р
 * 34.12-2015, ГОСТ 34.12-2018 and RFC 7801. It has been implemented
 * according to the reference document:
 *
 *   https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf (на русском)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The origin of this implementation goes far back in history. Its first
 * version has been based on the code written by Dr. Markku-Juhani O.
 * Saarinen (still accessible: https://github.com/mjosaarinen/kuznechik).
 * Our changes in the initial version included optimised portable 64-bit
 * code and, as an option, code optimised for CPUs with SSE extensions.
 *
 * The SSE version was supposed to be faster and it likely was at the time
 * of writing the code. But modern compilers have their own ways how to
 * optimise the compiled code and drastic manual optimisations may actually
 * prove detrimental to performance. The following benchmark speaks for
 * itself:
 *
 *   kuznyechik-kuzcrypt-ref ........... 152.684 MB/s (this version)
 *   kuznyechik-kuzcrypt-old-ref ....... 150.274 MB/s
 *   kuznyechik-kuzcrypt-old-sse ....... 148.737 MB/s
 *   kuznyechik-oliynykov-ref .......... 138.780 MB/s
 *   kuznyechik-saarinen-sse ........... 130.230 MB/s
 *   kuznyechik-veracrypt-ref .......... 148.082 MB/s
 *   kuznyechik-veracrypt-sse .......... 142.895 MB/s
 *
 * For this objective reason, we decided to remove the ‘optimised’ version
 * and keep the code portable. All versions were compiled with gcc and with
 * -Ofast turned on. Encryption was tested in the CBC mode.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This code is endian-independent.
 */
#include <stdbool.h>
#include "kuznyechik.h"

/*
 * The substitution table π′ for nonlinear mapping as defined in section 4.1.1
 * of the reference document.
 *
 *   π′ = (π′(0), π′(1), ... , π′(255))
 *
 * It should be noted that there is some controversy about the origins of the
 * values. The reference document does not comment on their origin and simply
 * enumerates them. The design criteria were not disclosed and this lack of
 * transparency led to concerns that there might be hidden vulnerabilities or
 * weaknesses exploitable by the FSB.
 *
 * Reverse engineering showed that the S-box has a hidden structure
 * (https://eprint.iacr.org/2016/071.pdf) but, as far as we know, there is
 * no PUBLICLY known hidden backdoor.
 */
static const unsigned char kuznyechik_pi[256] = {
	0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda,
	0x23, 0xc5, 0x04, 0x4d, 0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba,
	0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1, 0xf9, 0x18, 0x65, 0x5a,
	0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
	0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98,
	0x7f, 0xd4, 0xd3, 0x1f, 0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab,
	0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc, 0xb5, 0x70, 0x0e, 0x56,
	0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
	0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f,
	0x9d, 0x9e, 0xb2, 0xb1, 0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e,
	0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57, 0xdf, 0xf5, 0x24, 0xa9,
	0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
	0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50,
	0x4e, 0x33, 0x0a, 0x4a, 0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44,
	0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41, 0xad, 0x45, 0x46, 0x92,
	0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
	0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4,
	0x88, 0xd9, 0xe7, 0x89, 0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe,
	0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61, 0x20, 0x71, 0x67, 0xa4,
	0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
	0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2,
	0x39, 0x4b, 0x63, 0xb6
};

/*
 * Inversed π′ substitution box: reverses transformation by π′().
 *
 *   π⁻¹′ = (π⁻¹′(0), π⁻¹′(1), ... , π⁻¹′(255))
 */
static const unsigned char kuznyechik_pi_inv[256] = {
	0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0, 0x54, 0xe6, 0x9e, 0x39,
	0x55, 0x7e, 0x52, 0x91, 0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18,
	0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f, 0xe0, 0x27, 0x8d, 0x0c,
	0x82, 0xea, 0xae, 0xb4, 0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
	0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9, 0xaa, 0xfc, 0x4d, 0xbf,
	0x2a, 0x73, 0x84, 0xd5, 0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b,
	0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f, 0x9b, 0x43, 0xef, 0xd9,
	0x79, 0xb6, 0x53, 0x7f, 0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
	0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2, 0x4a, 0xbc, 0x35, 0xca,
	0xee, 0x78, 0x05, 0x6b, 0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11,
	0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c, 0x7b, 0x28, 0xab, 0xd2,
	0x31, 0xde, 0xc4, 0x5f, 0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
	0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1, 0x3b, 0x16, 0x66, 0xe9,
	0x5c, 0x6c, 0x6d, 0xad, 0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0,
	0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa, 0x96, 0x6f, 0x6e, 0xc2,
	0xf6, 0x50, 0xff, 0x5d, 0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
	0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67, 0x45, 0x87, 0xdc, 0xe8,
	0x4f, 0x1d, 0x4e, 0x04, 0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88,
	0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80, 0x90, 0xd0, 0x24, 0x34,
	0xcb, 0xed, 0xf4, 0xce, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
	0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7, 0xd6, 0x20, 0x0a, 0x08,
	0x00, 0x4c, 0xd7, 0x74
};

/*
 * Vector of constants used in linear transformation as defined in section
 * 4.1.2 of the reference document. It is used in the function l() which
 * multiplies each element of the input with a constant from this vector.
 */
static const unsigned char kuznyechik_linear_vector[16] = {
	0x94, 0x20, 0x85, 0x10, 0xc2, 0xc0, 0x01, 0xfb, 0x01, 0xc0, 0xc2, 0x10,
	0x85, 0x20, 0x94, 0x01
};

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * The polynomial for GF multiplication as defined in section 2.2
 * of the reference document:
 *
 *   p(x) = x⁸ + x⁷ + x⁶ + x + 1 ⇒ 0b11000011 = 0xc3
 */
#define GF_MUL_POLYNOMIAL 0xc3

static unsigned char gf_multtable_exp[256];
static unsigned char gf_multtable_log[256];

static unsigned char gf256_mul_fast(unsigned char a, unsigned char b)
{
	unsigned int c;

	if (a == 0 || b == 0) {
		return 0;
	}

	c = gf_multtable_log[a] + gf_multtable_log[b];

	return gf_multtable_exp[c % 255];
}

static unsigned char gf256_mul_slow(unsigned char a, unsigned char b)
{
	unsigned char c = 0;

	while (b) {
		if (b & 1) {
			c ^= a;
		}
		a = (a << 1) ^ (a & 0x80 ? GF_MUL_POLYNOMIAL : 0x00);
		b >>= 1;
	}
	return c;
}

static void gf256_init_tables()
{
	unsigned int c = 1;
	unsigned int i;

	for (i = 0; i < 256; i++) {
		gf_multtable_log[c] = i;
		gf_multtable_exp[i] = c;
		c = gf256_mul_slow(c, 0x03); /* a primitive generator */
	}
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * Linear mapping as defined in section 4.2.
 * Function R() is defined in section 4.1.2 and transforms the first element
 * of the input vector by the function l() whilst shifting the rest.
 *
 *   m = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
 *   l(a₀, …, a₁₅) = a₀·m₀ + a₁·m₁ + … + a₁₅·m₁₅
 *
 *   R(a) = R(a₀ ∥ … ∥ a₁₅) = l(a₀, …, a₁₅) ∥ a₀ ∥ … ∥ a₁₄, where a ∈ V₁₂₈
 *   L(a) = R¹⁶(a), where a ∈ V₁₂₈
 */
static void kuznyechik_linear(unsigned char *a)
{
	unsigned char l;
	int i, j;

	for (i = 0; i < 16; i++) {
		l = a[15];
		for (j = 14; j >= 0; j--) {
			a[j + 1] = a[j];
			l ^= gf256_mul_fast(a[j], kuznyechik_linear_vector[j]);
		}
		a[0] = l;
	}
}

/*
 * Inverse function to L() as defined in section 4.2.
 *
 *   L⁻¹(a) = (R⁻¹)¹⁶(a), where a ∈ V₁₂₈
 */
static void kuznyechik_linear_inv(unsigned char *a)
{
	unsigned char c;
	int i, j;

	for (i = 16; i; i--) {
		c = a[0];
		for (j = 0; j < 15; j++) {
			a[j] = a[j + 1];
			c ^= gf256_mul_fast(a[j], kuznyechik_linear_vector[j]);
		}
		a[15] = c;
	}
}

/* ────────────────────────────────────────────────────────────────────────── */

/*
 * The transformations of Kuznyechik can be optimised with lookup tables
 * containing precomputed values of the linear transformation performed
 * on zero vectors with a single byte set to a value x, where ∀x ∈ {0,…,255},
 * and transformed by the π′ function. In this way, encryption becomes
 * exclusively a series of XORs of values from the kuz_pil table and the round
 * subkeys. Decryption requires some additional transformation before XORing
 * the last round key.
 *
 * Let π′: ℤ₂⁸ → ℤ₂⁸ be the substitution function.
 * Let L: ℤ₂¹²⁸ → ℤ₂¹²⁸ be the linear transformation function.
 * Let eᵢ be a ℤ₂¹²⁸ with a single nonzero byte at position i.
 * Let π′⁻¹ be the inverse of π′.
 *
 * kuz_pil:
 *   Tᵢ​[x] = L(π′(x)·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_pil_inv:
 *   Tᵢ​[x] = L⁻¹(π′⁻¹(x)·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_l_inv:
 *   Tᵢ​[x] = L⁻¹(x·eᵢ​), ∀x ∈ {0,…,255}
 *
 * kuz_c:
 *   Tᵢ​[x] = L((x+1)·e₁₅), ∀x ∈ {0,…,31}
 */
static uint64_t kuz_pil[16][256][2];
static uint64_t kuz_pil_inv[16][256][2];
static uint64_t kuz_l_inv[16][256][2];
static uint64_t kuz_c[32][2];

static int kuznyechik_initialised = false;

static void kuznyechik_initialise_tables()
{
	unsigned int i, j;
	unsigned char *ptr;

	if (kuznyechik_initialised == true) {
		return;
	}

	gf256_init_tables();

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 256; j++) {
			/*
			 * Example for i = 1, j = 11:
			 *   π′(j) = 0xda
			 *   Tᵢ​[j] = L(0x00da0000000000000000000000000000)
			 *   Tᵢ​[j] = 0x127cd4effe23c12e3d1b513972c8577c
			 */
			ptr = (unsigned char *) kuz_pil[i][j];
			kuz_pil[i][j][0] = 0;
			kuz_pil[i][j][1] = 0;
			ptr[i] = kuznyechik_pi[j];
			kuznyechik_linear(ptr);

			/*
			 * Example for i = 7, j = 56:
			 *   π′⁻¹(j) = 0xaa
			 *   Tᵢ​[j] = L⁻¹(0x00000000000000aa0000000000000000)
			 *   Tᵢ​[j] = 0xaa1756ba36be19b344ee0a0d4d9d318e
			 */
			ptr = (unsigned char *) kuz_pil_inv[i][j];
			kuz_pil_inv[i][j][0] = 0;
			kuz_pil_inv[i][j][1] = 0;
			ptr[i] = kuznyechik_pi_inv[j];
			kuznyechik_linear_inv(ptr);

			/*
			 * Example for i = 2, j = 167:
			 *   j = 0xa7
			 *   Tᵢ​[j] = L⁻¹(0x0000a700000000000000000000000000)
			 *   Tᵢ​[j] = 0x074d7f867f7f6339fb898dff3be5d739
			 */
			ptr = (unsigned char *) kuz_l_inv[i][j];
			kuz_l_inv[i][j][0] = 0;
			kuz_l_inv[i][j][1] = 0;
			ptr[i] = j;
			kuznyechik_linear_inv(ptr);
		}
	}

	/*
	 * Generate constants for key schedule, section 4.3.
	 *
	 *   Cᵢ = L(Vec₁₂₈(i)), i = 1, 2, …, 32
	 */
	for (i = 0; i < 32; i++) {
		ptr = (unsigned char *) kuz_c[i];
		kuz_c[i][0] = 0;
		kuz_c[i][1] = 0;
		ptr[15] = (i + 1);
		kuznyechik_linear(ptr);
	}

	kuznyechik_initialised = true;
}

/* ────────────────────────────────────────────────────────────────────────── */

#define XOR_TABLE(lktab, a, b, i) (				\
	lktab[ 0][(((unsigned char *) &a)[0]) & 0xff][i] ^	\
	lktab[ 1][(((unsigned char *) &a)[1]) & 0xff][i] ^	\
	lktab[ 2][(((unsigned char *) &a)[2]) & 0xff][i] ^	\
	lktab[ 3][(((unsigned char *) &a)[3]) & 0xff][i] ^	\
	lktab[ 4][(((unsigned char *) &a)[4]) & 0xff][i] ^	\
	lktab[ 5][(((unsigned char *) &a)[5]) & 0xff][i] ^	\
	lktab[ 6][(((unsigned char *) &a)[6]) & 0xff][i] ^	\
	lktab[ 7][(((unsigned char *) &a)[7]) & 0xff][i] ^	\
	lktab[ 8][(((unsigned char *) &b)[0]) & 0xff][i] ^	\
	lktab[ 9][(((unsigned char *) &b)[1]) & 0xff][i] ^	\
	lktab[10][(((unsigned char *) &b)[2]) & 0xff][i] ^	\
	lktab[11][(((unsigned char *) &b)[3]) & 0xff][i] ^	\
	lktab[12][(((unsigned char *) &b)[4]) & 0xff][i] ^	\
	lktab[13][(((unsigned char *) &b)[5]) & 0xff][i] ^	\
	lktab[14][(((unsigned char *) &b)[6]) & 0xff][i] ^	\
	lktab[15][(((unsigned char *) &b)[7]) & 0xff][i]	\
)

#define KUZ_PI_INV (uint64_t) kuznyechik_pi_inv

#define INV_PI(a) (							\
	KUZ_PI_INV[(a >> (0 * 8)) & 0xff] << (0 * 8) |			\
	KUZ_PI_INV[(a >> (1 * 8)) & 0xff] << (1 * 8) |			\
	KUZ_PI_INV[(a >> (2 * 8)) & 0xff] << (2 * 8) |			\
	KUZ_PI_INV[(a >> (3 * 8)) & 0xff] << (3 * 8) |			\
	KUZ_PI_INV[(a >> (4 * 8)) & 0xff] << (4 * 8) |			\
	KUZ_PI_INV[(a >> (5 * 8)) & 0xff] << (5 * 8) |			\
	KUZ_PI_INV[(a >> (6 * 8)) & 0xff] << (6 * 8) |			\
	KUZ_PI_INV[(a >> (7 * 8)) & 0xff] << (7 * 8)			\
)

#define X(a, b, k1, k2)							\
	a ^= k1;							\
	b ^= k2;

#define SL(a, b, c, d)							\
	c = XOR_TABLE(kuz_pil, a, b, 0);				\
	d = XOR_TABLE(kuz_pil, a, b, 1);				\

#define IL(a, b, c, d)							\
	c = XOR_TABLE(kuz_l_inv, a, b, 0);				\
	d = XOR_TABLE(kuz_l_inv, a, b, 1);				\

#define ISL(a, b, c, d)							\
	c = XOR_TABLE(kuz_pil_inv, a, b, 0);				\
	d = XOR_TABLE(kuz_pil_inv, a, b, 1);				\

#define IS(a, b) {							\
	a = INV_PI(a);							\
	b = INV_PI(b);							\
}

#define FK(start, end) {						\
	for (i = start; i <= end; i++) {				\
		c[0] = a[0] ^ kuz_c[i - 1][0];				\
		c[1] = a[1] ^ kuz_c[i - 1][1];				\
		d[0] = XOR_TABLE(kuz_pil, c[0], c[1], 0);		\
		d[1] = XOR_TABLE(kuz_pil, c[0], c[1], 1);		\
									\
		d[0] ^= b[0];						\
		d[1] ^= b[1];						\
		b[0] = a[0];						\
		b[1] = a[1];						\
		a[0] = d[0];						\
		a[1] = d[1];						\
	}								\
}

/* ────────────────────────────────────────────────────────────────────────── */

int kuznyechik_set_key(struct kuznyechik_subkeys *subkeys,
		       const unsigned char *key)
{
	uint64_t a[2], b[2], c[2], d[2];
	uint64_t *ek = subkeys->ek;
	unsigned int i;

	if (kuznyechik_initialised == false) {
		kuznyechik_initialise_tables();
	}

	a[0] = ((uint64_t *) key)[0];
	a[1] = ((uint64_t *) key)[1];
	b[0] = ((uint64_t *) key)[2];
	b[1] = ((uint64_t *) key)[3];

	ek[0] = a[0];
	ek[1] = a[1];
	ek[2] = b[0];
	ek[3] = b[1];

	FK(1, 8);

	ek[4] = a[0];
	ek[5] = a[1];
	ek[6] = b[0];
	ek[7] = b[1];

	FK(9, 16);

	ek[8]  = a[0];
	ek[9]  = a[1];
	ek[10] = b[0];
	ek[11] = b[1];

	FK(17, 24);

	ek[12] = a[0];
	ek[13] = a[1];
	ek[14] = b[0];
	ek[15] = b[1];

	FK(25, 32);

	ek[16] = a[0];
	ek[17] = a[1];
	ek[18] = b[0];
	ek[19] = b[1];

	/*
	 * Keys for decryption - with applied L⁻¹().
	 */
	for (i = 0; i < 20; i += 2) {
		if (i == 0) {
			subkeys->dk[i + 0] = ek[i + 0];
			subkeys->dk[i + 1] = ek[i + 1];
			continue;
		}

		a[0] = ek[i + 0];
		a[1] = ek[i + 1];
		subkeys->dk[i + 0] = XOR_TABLE(kuz_l_inv, a[0], a[1], 0);
		subkeys->dk[i + 1] = XOR_TABLE(kuz_l_inv, a[0], a[1], 1);
	}

	return 0;
}

void kuznyechik_encrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in)
{
	uint64_t a, b, c, d, *k = subkeys->ek;

	a = ((uint64_t *) in)[0];
	b = ((uint64_t *) in)[1];

	/* round 1 */
	X(a, b, k[0], k[1]);
	SL(a, b, c, d);

	/* round 2 */
	X(c, d, k[2], k[3]);
	SL(c, d, a, b);

	/* round 3 */
	X(a, b, k[4], k[5]);
	SL(a, b, c, d);

	/* round 4 */
	X(c, d, k[6], k[7]);
	SL(c, d, a, b);

	/* round 5 */
	X(a, b, k[8], k[9]);
	SL(a, b, c, d);

	/* round 6 */
	X(c, d, k[10], k[11]);
	SL(c, d, a, b);

	/* round 7 */
	X(a, b, k[12], k[13]);
	SL(a, b, c, d);

	/* round 8 */
	X(c, d, k[14], k[15]);
	SL(c, d, a, b);

	/* round 9 */
	X(a, b, k[16], k[17]);
	SL(a, b, c, d);

	/* round 10 */
	X(c, d, k[18], k[19]);
	SL(c, d, a, b);

	((uint64_t *) out)[0] = c;
	((uint64_t *) out)[1] = d;
}

void kuznyechik_decrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out,
			const unsigned char *in)
{
	uint64_t a, b, c, d, *k = subkeys->dk;

	a = ((uint64_t *) in)[0];
	b = ((uint64_t *) in)[1];

	/* round 1 */
	IL(a, b, c, d);
	X(c, d, k[18], k[19]);

	/* round 2 */
	ISL(c, d, a, b);
	X(a, b, k[16], k[17]);

	/* round 3 */
	ISL(a, b, c, d);
	X(c, d, k[14], k[15]);

	/* round 4 */
	ISL(c, d, a, b);
	X(a, b, k[12], k[13]);

	/* round 5 */
	ISL(a, b, c, d);
	X(c, d, k[10], k[11]);

	/* round 6 */
	ISL(c, d, a, b);
	X(a, b, k[8], k[9]);

	/* round 7 */
	ISL(a, b, c, d);
	X(c, d, k[6], k[7]);

	/* round 8 */
	ISL(c, d, a, b);
	X(a, b, k[4], k[5]);

	/* round 9 */
	ISL(a, b, c, d);
	X(c, d, k[2], k[3]);

	/* round 10 */
	IS(c, d);
	X(c, d, k[0], k[1]);

	((uint64_t *) out)[0] = c;
	((uint64_t *) out)[1] = d;
}

void kuznyechik_wipe_key(struct kuznyechik_subkeys *subkeys)
{
	unsigned int i;

	for (i = 0; i < 20; i++) {
		subkeys->ek[i] = 0;
		subkeys->dk[i] = 0;
	}
}
