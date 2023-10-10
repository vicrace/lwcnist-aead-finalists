#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#ifndef PARAMS_H
#define PARAMS_H

// AEAD defines
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0 
#define CRYPTO_NPUBBYTES 16 
#define CRYPTO_ABYTES 16 
#define CRYPTO_NOOVERLAP 1 
// Hash defines
#define CRYPTO_BYTES 64000

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH_SIZE  5
#define ROMULUS_VER "M"			//version M - M1 nonce misuse-resistant , N - N1 nonce-based secure, T - leakage resillience AE mode
//#define WRITEFILE

//Romulus Ref
#define MSG_BLK_LEN 16
#define AD_BLK_LEN_ODD 16
#define AD_BLK_LEN_EVN 16


// Romulus M Op32
#include <stdint.h>
#define ___SKINNY_LOOP
//#define ___NUM_OF_ROUNDS_56
#define ___ENABLE_WORD_CAST

typedef struct ___skinny_ctrl {
#ifdef ___NUM_OF_ROUNDS_56
	uint32_t roundKeys[240]; // number of rounds : 56
#else
	uint32_t roundKeys[176]; // number of rounds : 40
#endif
	void (*func_skinny_128_384_enc)(unsigned char*, struct ___skinny_ctrl*, unsigned char* CNT, unsigned char* T, const unsigned char* K);
} skinny_ctrl;


extern void skinny_128_384_enc123_12(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
extern void skinny_128_384_enc12_12(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
extern void skinny_128_384_enc1_1(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
extern void Encrypt(unsigned char* block, uint32_t* roundKeys, unsigned char* sbox, unsigned char* sbox2);

__device__ extern void skinny_128_384_enc123_12G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void skinny_128_384_enc12_12G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void skinny_128_384_enc1_1G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void skinny_128_384_enc123_12G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void skinny_128_384_enc12_12G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void skinny_128_384_enc1_1G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K);
__device__ extern void EncryptG(unsigned char* block, uint32_t* roundKeys, unsigned char* sboxG, unsigned char* sbox2G);
__device__ extern void EncryptG_Op(unsigned char* block, uint32_t* roundKeys);

#define pack_word(x0, x1, x2, x3, w)    \
  w  = ((x3) << 24) ^                   \
       ((x2) << 16) ^                   \
       ((x1) << 8) ^                    \
       (x0);

#define unpack_word(x0, x1, x2, x3, w)  \
  x0  = ((w) & 0xff);                   \
  x1  = (((w) >> 8) & 0xff);            \
  x2  = (((w) >> 16) & 0xff);           \
  x3  = ((w) >> 24);


#define rho_ad_ud16_macro(i) \
  s[i] = s[i] ^ mp[i];


#define rho_ud16_macro(i)   \
  s[i] = s[i] ^ mp[i];

#define irho_ud16_macro(i)   \
  s[i] = s[i] ^ cp[i];

/////////////     Permutations    //////////////////

#define PERMUTATION()                                                             \
/* permutation */                                                                 \
                                                                                  \
  /* 7 6 5 4 3 2 1 0 */                                                           \
  /* 5 7 2 3 6 0 4 1 */                                                           \
                                                                                  \
  /* w0 (3 2 1 0) */                                                              \
  /* w1 (7 6 5 4) */                                                              \
                                                                                  \
  /* w0 (6 0 4 1) */                                                              \
  /* w1 (5 7 2 3) */                                                              \
                                                                                  \
  t0 = w1 << 8;         /* 6 5 4 - */                                             \
  t0 = t0 & 0xff00ff00; /* 6 - 4 - */                                             \
                                                                                  \
  t1 = w1 << 16;        /* 5 4 - - */                                             \
  t1 = t1 & 0xff000000; /* 5 - - - */                                             \
                                                                                  \
  t2 = w1 & 0xff000000; /* 7 - - - */                                             \
  t2 = t2 >> 8;         /* - 7 - - */                                             \
  t1 = t1 ^ t2;         /* 5 7 - - */                                             \
                                                                                  \
  t2 = w0 & 0xff000000; /* 3 - - - */                                             \
  t2 = t2 >> 24;        /* - - - 3 */                                             \
  t1 = t1 ^ t2;         /* 5 7 - 3 */                                             \
                                                                                  \
  w1 = w0 >> 8;         /* - 3 2 1 */                                             \
  w1 = w1 & 0x0000ff00; /* - - 2 - */                                             \
  w1 = w1 ^ t1;         /* 5 7 2 3 */                                             \
                                                                                  \
  t2 = w0 & 0x0000ff00; /* - - 1 - */                                             \
  t2 = t2 >> 8;         /* - - - 1 */                                             \
  t0 = t0 ^ t2;         /* 6 - 4 1 */                                             \
                                                                                  \
  w0 = w0 << 16;        /* 1 0 - - */                                             \
  w0 = w0 & 0x00ff0000; /* - 0 - - */                                             \
  w0 = w0 ^ t0;         /* 6 0 4 1 */ 



#define SBOX_0(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0)       ^                                                                \
      (t1 << 8)  ^                                                                \
      (t2 << 16) ^                                                                \
      (t3 << 24);

#define SBOX_8(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 8)  ^                                                                \
      (t1 << 16) ^                                                                \
      (t2 << 24) ^                                                                \
      (t3);

#define SBOX_16(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox2[t0];  /* AC(c2) */                                                   \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 16) ^                                                                \
      (t1 << 24) ^                                                                \
      (t2)       ^                                                                \
      (t3 << 8);

#define SBOX_24(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox[t0];                                                                  \
  t1 = sbox[t1];                                                                  \
  t2 = sbox[t2];                                                                  \
  t3 = sbox[t3];                                                                  \
                                                                                  \
  w = (t0 << 24) ^                                                                \
      (t1)       ^                                                                \
      (t2 << 8)  ^                                                                \
      (t3 << 16);


#define SKINNY_MAIN()                                                             \
                                                                                  \
  /* odd */                                                                       \
                                                                                  \
  /*  LUT(with ShiftRows) */                                                      \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* Load TK1 */                                                                  \
                                                                                  \
    w0 ^= *tk1++;                                                                 \
    w1 ^= *tk1++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;                                                                      \
                                                                                  \
  /* even */                                                                      \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0(w0);                                                                   \
    SBOX_8(w1);                                                                   \
    SBOX_16(w2);                                                                  \
    SBOX_24(w3);                                                                  \
                                                                                  \
  /* Load TK2^TK3^AC(c0 c1) */                                                    \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;

#define PERMUTATION_TK1()                                                         \
/* permutation */                                                                 \
                                                                                  \
  PERMUTATION();                                                                  \
                                                                                  \
  /* store */                                                                     \
                                                                                  \
  *tk1++ = w0;                                                                    \
  *tk1++ = w1;


#define PERMUTATION_TK2()                                                         \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION()                                                                 \
                                                                                  \
  /* LFSR(for TK2) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x6 x5 x4 x3 x2 x1 x0 x7^x5) */   \
    w0 = ((w0 << 1) & 0xfefefefe) ^                                               \
         (((w0 >> 7) ^ (w0 >> 5)) & 0x01010101);                                  \
    w1 = ((w1 << 1) & 0xfefefefe) ^                                               \
         (((w1 >> 7) ^ (w1 >> 5)) & 0x01010101);                                  \
                                                                                  \
  /* Load TK3 */                                                                  \
  /* TK2^TK3^AC(c0 c1) */                                                         \
  /* store */                                                                     \
    *tk2++ = w0 ^ *tk3++;                                                         \
    *tk2++ = w1 ^ *tk3++;                                                         \
    tk2 += 2;                                                                     \
    tk3 += 2;


#define PERMUTATION_TK3(c0Val, c1Val)                                             \
                                                                                  \
  /* permutation */                                                               \
                                                                                  \
    PERMUTATION()                                                                 \
                                                                                  \
  /* LFSR(for TK3) (x7 x6 x5 x4 x3 x2 x1 x0) -> (x0^x6 x7 x6 x5 x4 x3 x2 x1) */   \
    w0 = ((w0 >> 1) & 0x7f7f7f7f) ^                                               \
         (((w0 << 7) ^ (w0 << 1)) & 0x80808080);                                  \
    w1 = ((w1 >> 1) & 0x7f7f7f7f) ^                                               \
         (((w1 << 7) ^ (w1 << 1)) & 0x80808080);                                  \
                                                                                  \
  /* K3^AC(c0 c1) */                                                              \
  /* store */                                                                     \
    *tk3++ = w0 ^ c0Val;                                                          \
    *tk3++ = w1 ^ c1Val;                                                          \
    tk3 += 2;

#endif


////////////////// GPU SKINNY MAIN  /////////////////
#define SBOX_0G(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sboxG[t0];                                                                  \
  t1 = sboxG[t1];                                                                  \
  t2 = sboxG[t2];                                                                  \
  t3 = sboxG[t3];                                                                  \
                                                                                  \
  w = (t0)       ^                                                                \
      (t1 << 8)  ^                                                                \
      (t2 << 16) ^                                                                \
      (t3 << 24);

#define SBOX_8G(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sboxG[t0];                                                                  \
  t1 = sboxG[t1];                                                                  \
  t2 = sboxG[t2];                                                                  \
  t3 = sboxG[t3];                                                                  \
                                                                                  \
  w = (t0 << 8)  ^                                                                \
      (t1 << 16) ^                                                                \
      (t2 << 24) ^                                                                \
      (t3);

#define SBOX_16G(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sbox2G[t0];  /* AC(c2) */                                                   \
  t1 = sboxG[t1];                                                                  \
  t2 = sboxG[t2];                                                                  \
  t3 = sboxG[t3];                                                                  \
                                                                                  \
  w = (t0 << 16) ^                                                                \
      (t1 << 24) ^                                                                \
      (t2)       ^                                                                \
      (t3 << 8);

#define SBOX_24G(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = sboxG[t0];                                                                  \
  t1 = sboxG[t1];                                                                  \
  t2 = sboxG[t2];                                                                  \
  t3 = sboxG[t3];                                                                  \
                                                                                  \
  w = (t0 << 24) ^                                                                \
      (t1)       ^                                                                \
      (t2 << 8)  ^                                                                \
      (t3 << 16);


#define SKINNY_MAING()                                                             \
                                                                                  \
  /* odd */                                                                       \
                                                                                  \
  /*  LUT(with ShiftRows) */                                                      \
                                                                                  \
    SBOX_0G(w0);                                                                   \
    SBOX_8G(w1);                                                                   \
    SBOX_16G(w2);                                                                  \
    SBOX_24G(w3);                                                                  \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* Load TK1 */                                                                  \
                                                                                  \
    w0 ^= *tk1++;                                                                 \
    w1 ^= *tk1++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;                                                                      \
                                                                                  \
  /* even */                                                                      \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0G(w0);                                                                   \
    SBOX_8G(w1);                                                                   \
    SBOX_16G(w2);                                                                  \
    SBOX_24G(w3);                                                                  \
                                                                                  \
  /* Load TK2^TK3^AC(c0 c1) */                                                    \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;





//////////// Romulus M Op //////////

#define SBOX_0G_OP(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = SBOXG_Op[t0];                                                                  \
  t1 = SBOXG_Op[t1];                                                                  \
  t2 = SBOXG_Op[t2];                                                                  \
  t3 = SBOXG_Op[t3];                                                                  \
                                                                                  \
  w = (t0)       ^                                                                \
      (t1 << 8)  ^                                                                \
      (t2 << 16) ^                                                                \
      (t3 << 24);

#define SBOX_8G_OP(w)                                                                 \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = SBOXG_Op[t0];                                                                  \
  t1 = SBOXG_Op[t1];                                                                  \
  t2 = SBOXG_Op[t2];                                                                  \
  t3 = SBOXG_Op[t3];                                                                  \
                                                                                  \
  w = (t0 << 8)  ^                                                                \
      (t1 << 16) ^                                                                \
      (t2 << 24) ^                                                                \
      (t3);

#define SBOX_16G_OP(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = SBOXG2_Op[t0];  /* AC(c2) */                                                   \
  t1 = SBOXG_Op[t1];                                                                  \
  t2 = SBOXG_Op[t2];                                                                  \
  t3 = SBOXG_Op[t3];                                                                  \
                                                                                  \
  w = (t0 << 16) ^                                                                \
      (t1 << 24) ^                                                                \
      (t2)       ^                                                                \
      (t3 << 8);

#define SBOX_24G_OP(w)                                                                \
                                                                                  \
  t0 = (w) & 0xff;                                                                \
  t1 = (w >> 8) & 0xff;                                                           \
  t2 = (w >> 16) & 0xff;                                                          \
  t3 = (w >> 24);                                                                 \
                                                                                  \
  t0 = SBOXG_Op[t0];                                                                  \
  t1 = SBOXG_Op[t1];                                                                  \
  t2 = SBOXG_Op[t2];                                                                  \
  t3 = SBOXG_Op[t3];                                                                  \
                                                                                  \
  w = (t0 << 24) ^                                                                \
      (t1)       ^                                                                \
      (t2 << 8)  ^                                                                \
      (t3 << 16);


#define SKINNY_MAING_OP()                                                             \
                                                                                  \
  /* odd */                                                                       \
                                                                                  \
  /*  LUT(with ShiftRows) */                                                      \
                                                                                  \
    SBOX_0G_OP(w0);                                                                   \
    SBOX_8G_OP(w1);                                                                   \
    SBOX_16G_OP(w2);                                                                  \
    SBOX_24G_OP(w3);                                                                  \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* Load TK1 */                                                                  \
                                                                                  \
    w0 ^= *tk1++;                                                                 \
    w1 ^= *tk1++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;                                                                      \
                                                                                  \
  /* even */                                                                      \
                                                                                  \
  /* LUT(with ShiftRows & AC(c2) */                                               \
                                                                                  \
    SBOX_0G_OP(w0);                                                                   \
    SBOX_8G_OP(w1);                                                                   \
    SBOX_16G_OP(w2);                                                                  \
    SBOX_24G_OP(w3);                                                                  \
                                                                                  \
  /* Load TK2^TK3^AC(c0 c1) */                                                    \
                                                                                  \
    w0 ^= *tk2++;                                                                 \
    w1 ^= *tk2++;                                                                 \
                                                                                  \
  /* MC */                                                                        \
  /*  0 2 3 */                                                                    \
  /*  0 */                                                                        \
  /*  1 2 */                                                                      \
  /*  0 2 */                                                                      \
                                                                                  \
    /* 0^2 */                                                                     \
    t0 = w0 ^ w2;                                                                 \
                                                                                  \
    /* 1^2 */                                                                     \
    w2 = w1 ^ w2;                                                                 \
                                                                                  \
    /* 0 */                                                                       \
    w1 = w0;                                                                      \
                                                                                  \
    /* 0^2^3 */                                                                   \
    w0 = t0 ^ w3;                                                                 \
                                                                                  \
    /* 0^2 */                                                                     \
    w3 = t0;