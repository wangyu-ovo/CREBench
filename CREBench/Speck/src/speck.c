#include "speck.h"

#include "stdio.h"
#include "stdlib.h"

#define u32 uint32_t


#define ROR32(x,r) (((x)>>(r))|((x)<<(32-(r))))
#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define R(x,y,k) (x=ROR32(x,8), x+=y, x^=k, y=ROL32(y,3), y^=x)
#define RI(x,y,k) (y^=x, y=ROR32(y,3), x^=k, x-=y, x=ROL32(x,8))

#ifdef CONSTXOR_SPECK_TABLES
#include "constxor_tables.h"
#define SPECK_ROUND_CONSTANTS (constxor_speck_round_constants())
#else
static const u32 speck_round_constants[26] = {
  0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U,
  13U, 14U, 15U, 16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U
};
#define SPECK_ROUND_CONSTANTS (speck_round_constants)
#endif

static int Encrypt(u32 *u,u32 *v,u32 key[])
{
  u32 i,x=*u,y=*v;

  for(i=0;i<26;i++) R(x,y,key[i]);

  *u=x; *v=y;

  return 0;
}



  // int Decrypt(u32 *u,u32 *v,u32 key[])
  // {
  //   int i;
  //   u32 x=*u,y=*v;

  //   for(i=25;i>=0;i--) RI(x,y,key[i]);

  //   *u=x; *v=y;
  
  //   return 0;
  // }



static int ExpandKey(u32 K[],u32 key[])
{
  u32 i,C=K[2],B=K[1],A=K[0];

  for(i=0;i<26;i+=2){
    key[i]=A; R(B,A,SPECK_ROUND_CONSTANTS[i]);
    key[i+1]=A; R(C,A,SPECK_ROUND_CONSTANTS[i+1]);
  }

  return 0;
}

void speck_enc(const uint8_t in[SPECK_BLOCK_BYTES], uint8_t out[SPECK_BLOCK_BYTES], const uint8_t key[SPECK_KEY_BYTES]) {
  u32 expanded_key[26] = {0};
  ExpandKey((const u32*)key, expanded_key);
  u32 data[2] = {0};
  data[0] = (u32)in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
  data[1] = (u32)in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
  Encrypt(&data[0], &data[1], expanded_key);
    out[3] = (data[0] >> 24) & 0xFF;
    out[2] = (data[0] >> 16) & 0xFF;
    out[1] = (data[0] >> 8) & 0xFF;
    out[0] = data[0] & 0xFF;
    out[7] = (data[1] >> 24) & 0xFF;
    out[6] = (data[1] >> 16) & 0xFF;
    out[5] = (data[1] >> 8) & 0xFF;
    out[4] = data[1] & 0xFF;
}
