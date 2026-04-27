#include <string.h> // for memcpy
#include "sc2000.h"


#include <stdlib.h>
#include <stdint.h>
typedef int32_t s32;
typedef uint32_t u32;
typedef uint8_t u8;

#define T32(x)  ((x) & ONE32)
#define ONE32 0xffffffffU
#define ROTL32(v,n) (T32((v)<<(n))|((v)>>(32-(n))))

#ifdef CONSTXOR_SC2000_TABLES
#include "constxor_tables.h"
#define SC2000_S6_TABLE (constxor_sc2000_s6())
#define SC2000_S5_TABLE (constxor_sc2000_s5())
#define SC2000_S4_TABLE (constxor_sc2000_s4())
#define SC2000_S4I_TABLE (constxor_sc2000_s4i())
#define SC2000_M_TABLE (constxor_sc2000_m())
#else
/* S-boxes  (6-bit)(5-bit)  */
static const u32 S6[64] = {
  47, 59, 25, 42, 15, 23, 28, 39, 26, 38, 36, 19, 60, 24, 29, 56,
  37, 63, 20, 61, 55, 2, 30, 44, 9, 10, 6, 22, 53, 48, 51, 11,
  62, 52, 35, 18, 14, 46, 0, 54, 17, 40, 27, 4, 31, 8, 5, 12,
  3, 16, 41, 34, 33, 7, 45, 49, 50, 58, 1, 21, 43, 57, 32, 13
};
static const u32 S5[32] = {
  20, 26, 7, 31, 19, 12, 10, 15, 22, 30, 13, 14, 4, 24, 9, 18,
  27, 11, 1, 21, 6, 16, 2, 28, 23, 5, 8, 3, 0, 17, 29, 25
};

/* Bit-slice S-Box (4-bit)*/
/* 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15*/
static const u32 S4[16] = { 2, 5, 10, 12, 7, 15, 1, 11, 13, 6, 0, 9, 4, 8, 3, 14 };
static const u32 S4i[16] = { 10, 6, 0, 14, 12, 1, 9, 4, 13, 11, 2, 7, 3, 8, 15, 5 };

/* M-Table */
static const u32 M[32] = {
  0xd0c19225, 0xa5a2240a, 0x1b84d250, 0xb728a4a1,
  0x6a704902, 0x85dddbe6, 0x766ff4a4, 0xecdfe128,
  0xafd13e94, 0xdf837d09, 0xbb27fa52, 0x695059ac,
  0x52a1bb58, 0xcc322f1d, 0x1844565b, 0xb4a8acf6,
  0x34235438, 0x6847a851, 0xe48c0cbb, 0xcd181136,
  0x9a112a0c, 0x43ec6d0e, 0x87d8d27d, 0x487dc995,
  0x90fb9b4b, 0xa1f63697, 0xfc513ed9, 0x78a37d93,
  0x8d16c5df, 0x9e0c8bbe, 0x3c381f7c, 0xe9fb0779
};
#define SC2000_S6_TABLE (S6)
#define SC2000_S5_TABLE (S5)
#define SC2000_S4_TABLE (S4)
#define SC2000_S4I_TABLE (S4i)
#define SC2000_M_TABLE (M)
#endif

#define _A_ 0
#define _B_ 1
#define _C_ 2
#define _D_ 3
#define _X_ 0
#define _Y_ 1
#define _Z_ 2
#define _W_ 3
/* Order Table */
static const u32 Order[12][4] = {
  {_A_, _B_, _C_, _D_},
  {_B_, _A_, _D_, _C_},
  {_C_, _D_, _A_, _B_},
  {_D_, _C_, _B_, _A_},
  {_A_, _C_, _D_, _B_},
  {_B_, _D_, _C_, _A_},
  {_C_, _A_, _B_, _D_},
  {_D_, _B_, _A_, _C_},
  {_A_, _D_, _B_, _C_},
  {_B_, _C_, _A_, _D_},
  {_C_, _B_, _D_, _A_},
  {_D_, _A_, _C_, _B_}
};

/* Index Table */
static const u32 Index[9][4] = {
  {0, 0, 0, 0},
  {1, 1, 1, 1},
  {2, 2, 2, 2},
  {0, 1, 0, 1},
  {1, 2, 1, 2},
  {2, 0, 2, 0},
  {0, 2, 0, 2},
  {1, 0, 1, 0},
  {2, 1, 2, 1}
};

static void
S_func (u32 a, u32 * b)
{
  u32 q, r, s, t, u, v;
  q = (a >> 26) & 0x3F;
  r = (a >> 21) & 0x1F;
  s = (a >> 16) & 0x1F;
  t = (a >> 11) & 0x1F;
  u = (a >> 6) & 0x1F;
  v = (a >> 0) & 0x3F;
  q = SC2000_S6_TABLE[q];
  r = SC2000_S5_TABLE[r];
  s = SC2000_S5_TABLE[s];
  t = SC2000_S5_TABLE[t];
  u = SC2000_S5_TABLE[u];
  v = SC2000_S6_TABLE[v];
  *b = (q << 26);
  *b |= (r << 21);
  *b |= (s << 16);
  *b |= (t << 11);
  *b |= (u << 6);
  *b |= (v << 0);
  return;
}

static void
M_func (u32 a, u32 * b)
{
  s32 i;
  *b = 0;
  for (i = 31; i >= 0; i--)
    {
      if (a & 1)
        *b ^= SC2000_M_TABLE[i];
      a >>= 1;
    }
  return;
}

static void
L_func (u32 a, u32 b, u32 mask, u32 * c, u32 * d)
{
  u32 s, t;
  u32 imask = (mask ^ 0xFFFFFFFF);
  s = a & mask;
  t = b & imask;
  *c = s ^ b;
  *d = t ^ a;
  return;
}

static void
F_func (u32 a, u32 b, u32 mask, u32 * c, u32 * d)
{
  u32 s, t;
  S_func (a, &s);
  M_func (s, &s);
  S_func (b, &t);
  M_func (t, &t);
  L_func (s, t, mask, c, d);
  return;
}

static void
R_func (u32 a, u32 b, u32 c, u32 d, u32 mask, u32 * e,
        u32 * f, u32 * g, u32 * h)
{
  u32 s, t;
  F_func (c, d, mask, &s, &t);
  *e = a ^ s;
  *f = b ^ t;
  *g = c;
  *h = d;
  return;
}

static void
B_func (u32 a, u32 b, u32 c, u32 d, u32 * e, u32 * f, u32 * g, u32 * h)
{
  u32 s, t;
  u32 m = 1;
  s32 i;
  *e = 0;
  *f = 0;
  *g = 0;
  *h = 0;
  for (i = 0; i < 32; i++)
    {
      /*T_func */
      s = 0;
      if (a & m)
        s |= 8;
      if (b & m)
        s |= 4;
      if (c & m)
        s |= 2;
      if (d & m)
        s |= 1;
      t = SC2000_S4_TABLE[s];

      if (t & 8)
        *e |= m;
      if (t & 4)
        *f |= m;
      if (t & 2)
        *g |= m;
      if (t & 1)
        *h |= m;
      m <<= 1;
    }
  return;
}

static void
Bi_func (u32 a, u32 b, u32 c, u32 d, u32 * e, u32 * f, u32 * g, u32 * h)
{
  u32 s, t;
  u32 m = 1;
  s32 i;
  *e = 0;
  *f = 0;
  *g = 0;
  *h = 0;
  for (i = 0; i < 32; i++)
    {
      s = 0;
      /*T_func */
      if (a & m)
        s |= 8;
      if (b & m)
        s |= 4;
      if (c & m)
        s |= 2;
      if (d & m)
        s |= 1;
      t = SC2000_S4I_TABLE[s];

      if (t & 8)
        *e |= m;
      if (t & 4)
        *f |= m;
      if (t & 2)
        *g |= m;
      if (t & 1)
        *h |= m;
      m <<= 1;
    }
  return;
}

static void
I_func (u32 a, u32 b, u32 c, u32 d, u32 ka, u32 kb,
        u32 kc, u32 kd, u32 * e, u32 * f, u32 * g, u32 * h)
{
  *e = a ^ ka;
  *f = b ^ kb;
  *g = c ^ kc;
  *h = d ^ kd;
  return;
}

static u32
make_one_imkey (u32 k1, u32 k2, u32 i, u32 j)
{
  u32 ka, kb, m;
  ka = k1;
  S_func (ka, &ka);
  M_func (ka, &ka);
  kb = k2;
  S_func (kb, &kb);
  M_func (kb, &kb);
  m = 4 * i + j;
  S_func (m, &m);
  M_func (m, &m);
  ka += m;
  ka &= 0xFFFFFFFF;
  kb *= (i + 1);
  kb &= 0xFFFFFFFF;
  ka ^= kb;
  S_func (ka, &ka);
  M_func (ka, &ka);
  return (ka);
}

static void
make_imkeys (u32 * ukey, u32 keylength, u32 imkey[4][3])
{
  u32 kl, k2, k3, k4, k5, k6, k7, k8;
  u32 i;
  kl = ukey[0];
  k2 = ukey[1];
  k3 = ukey[2];
  k4 = ukey[3];

  k5 = ukey[4];
  k6 = ukey[5];
  k7 = ukey[6];
  k8 = ukey[7];

  for (i = 0; i < 3; i++)
    {
      imkey[_A_][i] = make_one_imkey (kl, k2, i, 0);
      imkey[_B_][i] = make_one_imkey (k3, k4, i, 1);
      imkey[_C_][i] = make_one_imkey (k5, k6, i, 2);
      imkey[_D_][i] = make_one_imkey (k7, k8, i, 3);
    }
}

static u32
make_one_ekey (u32 imkey[4][3], u32 t, u32 s)
{
  u32 x, y, z, w;
  x = imkey[Order[t][_X_]][Index[s][_X_]];
  y = imkey[Order[t][_Y_]][Index[s][_Y_]];
  z = imkey[Order[t][_Z_]][Index[s][_Z_]];
  w = imkey[Order[t][_W_]][Index[s][_W_]];
  x = ROTL32 (x, 1);
  x += y;
  x &= 0xFFFFFFFF;
  z = ROTL32 (z, 1);
  z -= w;
  z &= 0xFFFFFFFF;
  z = ROTL32 (z, 1);
  x ^= z;
  return (x);
}

static void
make_ekeys (u32 imkey[4][3], u32 num_ekey, u32 * ekey)
{
  u32 n, t, s;
  for (n = 0; n < num_ekey; n++)
    {
      t = (n + (n / 36)) % 12;
      s = n % 9;
      ekey[n] = make_one_ekey (imkey, t, s);
    }
}


static void setup (u32 * ukey, u32 ek[64])
{
  u32 imkey[4][3];
  /* make intermediate key */
  make_imkeys (ukey, 256, imkey);

  /* make extend key */
  make_ekeys (imkey, 64, ek);



}

static void crypt (u32 * in, u32 ek[64])
{
  u32 a, b, c, d;
  a = in[0];
  b = in[1];
  c = in[2];
  d = in[3];
  I_func (a, b, c, d, ek[0], ek[1], ek[2], ek[3], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[4], ek[5], ek[6], ek[7], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[8], ek[9], ek[10], ek[11], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[12], ek[13], ek[14], ek[15], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[16], ek[17], ek[18], ek[19], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[20], ek[21], ek[22], ek[23], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[24], ek[25], ek[26], ek[27], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[28], ek[29], ek[30], ek[31], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[32], ek[33], ek[34], ek[35], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[36], ek[37], ek[38], ek[39], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[40], ek[41], ek[42], ek[43], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[44], ek[45], ek[46], ek[47], &a, &b, &c, &d);
  R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
  R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[48], ek[49], ek[50], ek[51], &a, &b, &c, &d);
  B_func (a, b, c, d, &a, &b, &c, &d);
  I_func (a, b, c, d, ek[52], ek[53], ek[54], ek[55], &a, &b, &c, &d);

  in[0] = a;
  in[1] = b;
  in[2] = c;
  in[3] = d;
}

// static void
// decrypt (u32 * in, u32 ek[64])
// {

//   u32 a, b, c, d;

//   a = in[0];
//   b = in[1];
//   c = in[2];
//   d = in[3];

//   I_func (a, b, c, d, ek[52], ek[53], ek[54], ek[55], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[48], ek[49], ek[50], ek[51], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[44], ek[45], ek[46], ek[47], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[40], ek[41], ek[42], ek[43], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[36], ek[37], ek[38], ek[39], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[32], ek[33], ek[34], ek[35], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[28], ek[29], ek[30], ek[31], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[24], ek[25], ek[26], ek[27], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[20], ek[21], ek[22], ek[23], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[16], ek[17], ek[18], ek[19], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x33333333, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x33333333, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[12], ek[13], ek[14], ek[15], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[8], ek[9], ek[10], ek[11], &a, &b, &c, &d);
//   R_func (a, b, c, d, 0x55555555, &a, &b, &c, &d);
//   R_func (c, d, a, b, 0x55555555, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[4], ek[5], ek[6], ek[7], &a, &b, &c, &d);
//   Bi_func (a, b, c, d, &a, &b, &c, &d);
//   I_func (a, b, c, d, ek[0], ek[1], ek[2], ek[3], &a, &b, &c, &d);

//   in[0] = a;
//   in[1] = b;
//   in[2] = c;
//   in[3] = d;
// }




void sc2000_enc(const u8 in[SC2000_BLOCK_BYTES], 
                u8 out[SC2000_BLOCK_BYTES], 
                const u8 key[SC2000_KEY_BYTES]) {
    u32 ek[64];
    u32 key_words[8];
    u32 block[4];

    memcpy(key_words, key, SC2000_KEY_BYTES);
    setup(key_words, ek);
    memcpy(block, in, SC2000_BLOCK_BYTES);
    crypt(block, ek);
    memcpy(out, block, SC2000_BLOCK_BYTES);
}
