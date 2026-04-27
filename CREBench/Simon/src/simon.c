#include "simon.h"

#include "stdio.h"
#include "stdlib.h"

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t

#define ROR32(x,r) (((x)>>(r))|((x)<<(32-(r))))
#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define f(x) ((ROL32(x,1) & ROL32(x,8)) ^ ROL32(x,2))
#define R2(x,y,k,l) (y^=f(x), y^=k, x^=f(y), x^=l)

#ifdef CONSTXOR_SIMON_TABLES
#include "constxor_tables.h"
#define SIMON_MAGIC_TABLE (constxor_simon_magic())
#else
static const u64 simon_magic[2] = {0xFFFFFFFCULL, 0x7369F885192C0EF5ULL};
#define SIMON_MAGIC_TABLE (simon_magic)
#endif

static int Encrypt(u32 *u,u32 *v,u32 key[])
{
  u32 i,x=*u,y=*v;
  for(i=0;i<42;i+=2) R2(x,y,key[i],key[i+1]);

  *u=x; *v=y;

  return 0;
}



// int Decrypt(u32 *u,u32 *v,u32 key[])
// {
//   int i;
//   u32 x=*u,y=*v;

//   for(i=41;i>=0;i-=2) R2(y,x,key[i],key[i-1]);

//   *u=x; *v=y;

//   return 0;
// }



static int ExpandKey(const u32 K[],u32 key[])
{
  u32 i,c=(u32)SIMON_MAGIC_TABLE[0];
  u64 z=SIMON_MAGIC_TABLE[1];

  key[0]=K[0]; key[1]=K[1]; key[2]=K[2];

  for(i=3;i<42;i++){
    key[i]=c^(z&1)^key[i-3]^ROR32(key[i-1],3)^ROR32(key[i-1],4); 
    z>>=1;
  }

  return 0;
}

void simon_enc(const uint8_t in[SIMON_BLOCK_BYTES], uint8_t out[SIMON_BLOCK_BYTES], const uint8_t key[SIMON_KEY_BYTES]) {
  u32 expanded_key[42] = {0};
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
