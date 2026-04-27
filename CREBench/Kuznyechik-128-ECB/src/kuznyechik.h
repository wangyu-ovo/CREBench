/*
 * Kuznyechik / GOST R 34.12-2015
 * National Standard of the Russian Federation
 *
 * Based on the reference implementation from:
 * https://github.com/vlastavesely/kuznechik
 *
 * For educational and CTF purposes only.
 */
#ifndef __KUZNYECHIK_H
#define __KUZNYECHIK_H

#include <stdint.h>
#include <stddef.h>

#if defined (__cplusplus)
extern "C" {
#endif

#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_KEY_SIZE 32

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

/* ECB mode: encrypt multiple blocks */
void kuznyechik_ecb_encrypt(struct kuznyechik_subkeys *subkeys,
                            const unsigned char *in,
                            unsigned char *out,
                            size_t len);

/* ECB mode: decrypt multiple blocks */
void kuznyechik_ecb_decrypt(struct kuznyechik_subkeys *subkeys,
                            const unsigned char *in,
                            unsigned char *out,
                            size_t len);

#if defined (__cplusplus)
}
#endif

#endif /* __KUZNYECHIK_H */



