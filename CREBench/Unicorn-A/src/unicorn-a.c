#include "unicorn-a.h"
#include <string.h> // memcpy

typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;

#define IK0 0
#define IK4 ROUND*16+16
#define EK0 IK0+16

#define ROUND    16
#define LINE     8

#ifdef CONSTXOR_UNICORN_TABLES
#include "constxor_tables.h"
#define UNICORN_S_TABLE (constxor_unicorn_s())
#else
static const u32 S[256] =
{
  0x95ae2518, 0x6fff22fc, 0xeda1a290, 0x9b6d8479,
  0x15fe8611, 0x5528dc2a, 0x6c5f5b4d, 0x4c438f7f,
  0xec212902, 0x4b7c2d23, 0xc185e5ad, 0x543af715,
  0x16e06281, 0x8aeeb23a, 0x59814469, 0x37383871,
  0x3389d470, 0x913961e5, 0x0da946b9, 0x99570fbd,
  0x94dd3a4c, 0xa3dc48cc, 0x56a3d8d1, 0x3b54d057,
  0xcc0e0e05, 0xafef6060, 0x5babd652, 0x758ad963,
  0x7e4a8585, 0x46c0b38c, 0x90421c42, 0x0a689a40,
  0xf80878c0, 0x92fa7b6b, 0xc92b53c2, 0x007364dc,
  0x617eeb10, 0xd0580344, 0x17d4e6b7, 0xd667a0ab,
  0x933ec1db, 0xea52f533, 0x428fa45c, 0x41049b0d,
  0xe275ff98, 0x39e2af56, 0xd21c4f87, 0xe09b947b,
  0xac41e362, 0x289cdbae, 0x9a8b1767, 0x57b75f9c,
  0xb2eb6f9d, 0xeb7d0b3b, 0x87d95791,0xdc74689b,
  0x6e6fa39e, 0x79edcb08, 0x609dbde7, 0x08441d84,
  0x09a09c53, 0x35b8ad31, 0xf1d5d317, 0x69ac4020,
  0x8faa9d55, 0xa9843545, 0xb649c4fb, 0x8b025924,
  0x700151e9, 0x10e804ee, 0xb75c54de, 0x43f91095,
  0xe988c025, 0x276a4af8, 0xc5af0d1a, 0x4a05b512,
  0xa609147d, 0xda8cb80b, 0xe7263989, 0xf2bfb7fd,
  0xa1325a4f, 0x9ffb7734, 0xc0555d38, 0x250ccf5f,
  0xb11b26f1, 0xe43083bb, 0x2f2e5e2c, 0x77343ca7,
  0x0e91747c, 0x124e0166, 0xf4a8d5e3, 0x389f7a73,
  0x036405d4, 0xc3bc658e, 0xef10909a, 0xdbe3755d,
  0x211a4bf7, 0xa7c62ed3, 0x1af40821, 0xb4cdac1c,
  0x36b2aa43, 0x3d48980a, 0x3a8ee793, 0xdea2d2e1,
  0x043342d7, 0x1ef636d2, 0xbff10af6, 0x2280bba0,
  0x6bc28083, 0xf9b1cc49, 0x8e7a0c41, 0x96146639,
  0x5f90f301, 0x2a3173b6, 0x7c5389b4, 0x19a693c7,
  0xe8f79fcf, 0xb5e1e97e, 0x780b3bd8, 0x5d07dde0,
  0x0566fd3d, 0x44f27051, 0x06b9a5ca, 0x3012c6c4,
  0x81966992, 0x29a5debc, 0x6879ea77, 0x49629980,
  0xbc5d2b32, 0xa5c5c91e, 0xd446795b, 0xa097b4a1,
  0xfa4b5659, 0x8d76cd0c, 0x7bcae1c3, 0xd8d8f24a,
  0x5e6cb6eb, 0xeecf37df, 0x510f3fe2, 0xca70e8ac,
  0x0763fef5, 0x7a232c07, 0xc46509da, 0x1145159f,
  0xcf5688f2, 0x663d41d9, 0xb84f72d0, 0xbd6e1f26,
  0xf30d28a3, 0x48da312d, 0xce950027, 0x0c062404,
  0xc886a93e, 0xe11d1688, 0xa424f968, 0xb08323b3,
  0xf7b53e58, 0x019a11c5, 0x02b4ae06, 0xfee6f800,
  0x474d9e8d, 0xb9c197be, 0xe5a418f3, 0xbb1132d6,
  0xfbd3b06d, 0x89036ca2, 0x45d1433c, 0xa8697fa5,
  0x325e96c6, 0x18ce12e4, 0xab2c02dd, 0xad13a8a4,
  0x9e3cc26a, 0xdd7bab65, 0x7f0ac3cb, 0x1b1f91ec,
  0xfc82638f, 0x72c31930, 0x984c506e, 0x52d0e050,
  0xd13621b0, 0x26fcc84e, 0xcbdbc5ea, 0x80cb76b5,
  0xd7c7a161, 0xd5273d54, 0x24bd8e14, 0xae504d46,
  0x86a7be1d, 0xb35ad1a8, 0x5a20301b, 0x761e8b48,
  0x50e9ee47, 0xf640ce5a, 0xfdf52aff, 0x7db67d13,
  0x1d78effe, 0x2ce7ed72, 0x0f7f3419, 0xe32fdfe6,
  0x6216582f, 0xcd87a72b, 0xff371a64, 0x4d7282b2,
  0xc6ea4c28, 0xc229bf29, 0x851507f9, 0x825147ba,
  0x4fadd796, 0x67df1bcd, 0x4e177eb8, 0x31fd06c9,
  0x1399fb8b, 0x8c19334b, 0x6d2df136, 0xd3f88116,
  0xdf61873f, 0x3fb3f6f4, 0x40baf46c, 0x977792af,
  0x3ec8202e, 0xd992b1a9, 0xaabb49f0, 0x53d25299,
  0x8800e297, 0x2de46e74, 0x73184e7a, 0xc7bebae8,
  0x148df0a6, 0x2eec8d75, 0xbe3fa60e, 0xf0c9455e,
  0x84606b6f, 0x1c7155ce, 0xa2f067ed, 0xe69395b1,
  0x83e5fac8, 0x6a5b6d1f, 0x206bcaaa, 0x58d61378,
  0x9d5971d5, 0x1f3b8c35, 0x2b988a94, 0x9cd7270f,
  0x71b0b937, 0xbacce4ef, 0x23f36a03, 0x65942fbf,
  0x342afc86, 0x3c9ec7fa, 0x0b47bcc1, 0x64225c09,
  0x74deda82, 0xf5251e76, 0x63c4ec8a, 0x5c357c22
};
#define UNICORN_S_TABLE (S)
#endif


static void F (u32, u32, u32*, u32*, u32*);
static void unicorn_key_schedule(const u8 *secret, u8 eKey[288]);


void unicorn_enc(const u8 in[UNICORN_BLOCK_BYTES], u8 out[UNICORN_BLOCK_BYTES], const u8 key[UNICORN_KEY_BYTES])
{
  u32   wx[4],tmp[2];
  s32 i;
  u8   eKey[288];
  unicorn_key_schedule(key, eKey);
  memcpy(out, in, UNICORN_BLOCK_BYTES);
  u8 *src = out;
  for (i = 0 ; i < 4 ; i++)
    {
      wx[i]   = src[i*4] << 24;
      wx[i]   |= src[i*4+1] << 16;
      wx[i]   |= src[i*4+2] << 8;
      wx[i]   |= src[i*4+3];
    }
  for (i = 0 ; i < 4 ; i++)
    {
      wx[i] += *((u32 *)(eKey+(IK0+i*4)));
    }
    
  for (i = 0 ; i < ROUND ; i++)
    {
      F(wx[2], wx[3], (u32 *)&eKey[EK0+(i *16)], &tmp[0], &tmp[1]);
      tmp[0] ^= wx[0];
      tmp[1] ^= wx[1];
      wx[0] = wx[2];
      wx[1] = wx[3];
      wx[2] = tmp[0];
      wx[3] = tmp[1];
    }

  wx[0] -= *((u32 *)(eKey+(IK4+8)));
  wx[1] -= *((u32 *)(eKey+(IK4+12)));
  wx[2] -= *((u32 *)(eKey+(IK4)));
  wx[3] -= *((u32 *)(eKey+(IK4+4)));

  src[0] = (u8) (wx[2] >> 24) ;
  src[1] = (u8)(wx[2] >> 16);
  src[2] = (u8) (wx[2] >> 8) ;
  src[3] = (u8) (wx[2]) ;
  src[4] = (u8)(wx[3] >> 24);
  src[5] = (u8)(wx[3] >> 16);
  src[6] = (u8) (wx[3] >> 8) ;
  src[7] = (u8) (wx[3]);
  src[8] = (u8)(wx[0] >> 24);
  src[9] = (u8)(wx[0] >> 16);
  src[10] = (u8)(wx[0] >> 8);
  src[11] = (u8) (wx[0]);
  src[12] = (u8)(wx[1] >> 24);
  src[13] = (u8)(wx[1] >> 16);
  src[14] = (u8)(wx[1] >> 8);
  src[15] = (u8) (wx[1]);
}

static void F(u32 ida, u32 idb, u32 *k, u32 *oda, u32 *odb)
{
  u32   wx0,wx1,wk0,wk1,tmp;
  wx0 = ida + k[0];
  wx1 = idb + k[2];
  wk0 = idb + k[1];
  wk1 = ida + k[3];
  tmp = wx0^wx0<<23^wx1>>9^wx0>>23^wx1<9;
  wx1 = wx1^wx1<23^wx0>>9^wx1>>23^wx0<<9;
  wx0 = tmp * 0x7e167289;
  wx1 ^= UNICORN_S_TABLE[ wx0>>24 ];
  wx1 *= 0xfe21464b;
  wx0 ^= UNICORN_S_TABLE[ wx1>>24 ];
  wx1 ^= UNICORN_S_TABLE[(wx0>>16)&0xff];
  wx0 ^= UNICORN_S_TABLE[(wx1>>16)&0xff];
  wx1 ^= UNICORN_S_TABLE[(wx0>> 8)&0xff];
  wx0 ^= UNICORN_S_TABLE[(wx1>> 8)&0xff];
  wx1 ^= UNICORN_S_TABLE[wx0&0xff];
  wx0 ^= UNICORN_S_TABLE[wx1&0xff];
  wk0 *= 0x7e167289;
  wk1 ^= UNICORN_S_TABLE[ wk0>>24 ];
  wk1 *= 0xfe21464b;
  wk0 ^= UNICORN_S_TABLE[ wk1>>24 ];
  wk0 *= 0xfe21464b;
  wk1 ^= UNICORN_S_TABLE[ wk0>>24];
  wk1 *= 0x7e167289;
  wk0 ^= UNICORN_S_TABLE[ wk1>>24];
  wk1 ^= UNICORN_S_TABLE[(wk0>>16)&0xff];
  wk0 ^= UNICORN_S_TABLE[(wk1>>16)&0xff];
  wx1 ^= UNICORN_S_TABLE[(wx0>>(24-((wk1&0xc)<<1)))&0xff];
  wx0 ^= UNICORN_S_TABLE[(wx1>>(24-((wk1&0x3)*8)))&0xff];
  *oda = wx0 ^ wk0;
  *odb = wx1 ^ wk0;
  return;
}


static void unicorn_key_schedule(const u8 *secret, u8 eKey[288])
{
  u32   wk[LINE], ek[1000];
  s32   i,j, n = ROUND+2;
  s32   cnt = 0;

  for (i = 0 ; i < LINE ; i++)
    {
      wk[i]   = secret[i*4]<<24 | secret[i*4+1]<<16 | secret[i*4+2]  << 8 | secret[i*4+3];
    }


  for (i = 0 ; i < 3 ; i++)
    {
      for (j = 0 ; j < LINE ; j++)
        {
          wk[j] *= 0x01010101;
          wk[(j+1)%LINE] ^= UNICORN_S_TABLE[ wk[j]>>24 ];
        }
    }

  for (i = 0 ; i < 16*((ROUND+2)/2) ; i+=16)
    {
      for (j = i ; j < (i+8) ; j++)
        {
          wk[j%LINE] *= 0x01010101;
          wk[(j+1)%LINE]^=UNICORN_S_TABLE[wk[j%LINE]>>24];
        }

      for ( ; j < (i+16) ; j++)
        {
          wk[j%LINE] *= 0x01010101;
          ek[cnt++] = wk[(j+1)%LINE] ^= UNICORN_S_TABLE[ wk[j%LINE]>>24 ];
        }
    }
  memcpy(&eKey[IK0], &ek[0], 4);
  memcpy(&eKey[IK0+4], &ek[n], 4) ;
  memcpy(&eKey[IK0+8], &ek[n*2], 4) ;
  memcpy(&eKey[IK0+12], &ek[n*3], 4);
  memcpy(&eKey[IK4], &ek[n-1], 4);
  memcpy(&eKey[IK4+4], &ek[n*2-1], 4);
  memcpy(&eKey[IK4+8], &ek[n*3-1], 4);
  memcpy(&eKey[IK4+12], &ek[n*4-1], 4);
  for (i = 1 ; i <= ROUND ; i++)
    {
      memcpy(&eKey[EK0*i], &ek[i], 4);
      memcpy(&eKey[EK0*i+4], &ek[n+i], 4);
      memcpy(&eKey[EK0*i+8], &ek[n*2+i], 4);
      memcpy(&eKey[EK0* i +12], &ek[n*3+ i], 4);
    }
  return;
}
