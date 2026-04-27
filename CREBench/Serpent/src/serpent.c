#include <stdbool.h>
#include "serpent.h"
#include "serpentp.h"

void serpent_enc(const uint8_t in[SERPENT_BLOCK_BYTES], uint8_t out[SERPENT_BLOCK_BYTES], const uint8_t key[SERPENT_KEY_BYTES])
{
    uint32_t a, b, c, d, e;
    uint32_t transformed_key[SERPENT_TRANSFORMED_KEY_WORDS] = {0};
    serpent_key_schedule(transformed_key, SERPENT_ROUNDS, key, SERPENT_KEY_BYTES);
	// puts("Key ready");
	// for (int i = 0; i < SERPENT_TRANSFORMED_KEY_WORDS; i++) {
	// 	printf("k[%d] = %08x\n", i, transformed_key[i]);
	// }
	a = ((uint32_t)in[0]) |
		((uint32_t)in[1] <<  8) |
		((uint32_t)in[2] <<  16) |
		((uint32_t)in[3] <<  24);
	b = ((uint32_t)in[4]) |
		((uint32_t)in[5] <<  8) |
		((uint32_t)in[6] <<  16) |
		((uint32_t)in[7] <<  24);
	c = ((uint32_t)in[8]) |
		((uint32_t)in[9] <<  8) |
		((uint32_t)in[10] <<  16) |
		((uint32_t)in[11] <<  24);
	d = ((uint32_t)in[12]) |
		((uint32_t)in[13] <<  8) |
		((uint32_t)in[14] <<  16) |
		((uint32_t)in[15] <<  24);
	// printf("Input block: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    uint32_t *k = transformed_key;
    unsigned int i = 1;
    do
	{
		beforeS0(KX); beforeS0(S0); afterS0(LT);
		afterS0(KX); afterS0(S1); afterS1(LT);
		afterS1(KX); afterS1(S2); afterS2(LT);
		afterS2(KX); afterS2(S3); afterS3(LT);
		afterS3(KX); afterS3(S4); afterS4(LT);
		afterS4(KX); afterS4(S5); afterS5(LT);
		afterS5(KX); afterS5(S6); afterS6(LT);
		afterS6(KX); afterS6(S7);

		if (i == 4)
			break;

		++i;
		c = b;
		b = e;
		e = d;
		d = a;
		a = e;
		k += 32;
		beforeS0(LT);
		// printf("Round %d complete: a=%08x b=%08x c=%08x d=%08x e=%08x\n", i-1, a, b, c, d, e);
	}
	while (true);

	afterS7(KX);
	out[0] = (uint8_t)(d      );
	out[1] = (uint8_t)(d >>  8);
	out[2] = (uint8_t)(d >> 16);
	out[3] = (uint8_t)(d >> 24);
	out[4] = (uint8_t)(e      );
	out[5] = (uint8_t)(e >>  8);
	out[6] = (uint8_t)(e >> 16);
	out[7] = (uint8_t)(e >> 24);
	out[8] = (uint8_t)(b      );
	out[9] = (uint8_t)(b >>  8);
	out[10] = (uint8_t)(b >> 16);
	out[11] = (uint8_t)(b >> 24);
	out[12] = (uint8_t)(a      );
	out[13] = (uint8_t)(a >>  8);
	out[14] = (uint8_t)(a >> 16);
	out[15] = (uint8_t)(a >> 24);
}
