#include "serpent.h"
#include "serpentp.h"

#ifdef CONSTXOR_SERPENT_TABLES
#include "constxor_tables.h"
#define SERPENT_MAGIC_TABLE (constxor_serpent_magic())
#define SERPENT_DELTA_VALUE (SERPENT_MAGIC_TABLE[0])
#else
static const uint32_t serpent_magic[1] = {0x9E3779B9U};
#define SERPENT_DELTA_VALUE (serpent_magic[0])
#endif

void serpent_key_schedule(uint32_t *k, unsigned int rounds, const uint8_t *userKey, size_t keylen)
{
	uint32_t k0[8] = {0};
    for (size_t i = 0; i < keylen/4; ++i)
        k0[i] = ((uint32_t)userKey[4*i    ]      ) |
                ((uint32_t)userKey[4*i + 1] <<  8) |
                ((uint32_t)userKey[4*i + 2] << 16) |
                ((uint32_t)userKey[4*i + 3] << 24);
	if (keylen < 32)
		k0[keylen/4] |= (uint32_t)(1) << ((keylen%4)*8);
	// for (int i = 0; i < 8; ++i)
	// 	printf("k0[%d] = %08x\n", i, k0[i]);

	uint32_t t = k0[7];
	unsigned int i;
	for (i = 0; i < 8; ++i)
		k[i] = k0[i] = t = rotlConstant(k0[i] ^ k0[(i + 3) % 8] ^ k0[(i + 5) % 8] ^ t ^ SERPENT_DELTA_VALUE ^ i, 11);
	for (i = 8; i < 4*(rounds+1); ++i)
		k[i] = t = rotlConstant(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ SERPENT_DELTA_VALUE ^ i, 11);
	k -= 20;

	uint32_t a,b,c,d,e;
	for (i=0; i<rounds/8; i++)
	{
		afterS2(LK); afterS2(S3); afterS3(SK);
		afterS1(LK); afterS1(S2); afterS2(SK);
		afterS0(LK); afterS0(S1); afterS1(SK);
		beforeS0(LK); beforeS0(S0); afterS0(SK);
		k += 8*4;
		afterS6(LK); afterS6(S7); afterS7(SK);
		afterS5(LK); afterS5(S6); afterS6(SK);
		afterS4(LK); afterS4(S5); afterS5(SK);
		afterS3(LK); afterS3(S4); afterS4(SK);
	}
	afterS2(LK); afterS2(S3); afterS3(SK);
}
