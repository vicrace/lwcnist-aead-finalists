// GPU
#define CRYPTO_KEYBYTES     16
#define CRYPTO_NSECBYTES    0
#define CRYPTO_NPUBBYTES    16
#define CRYPTO_ABYTES       16
#define CRYPTO_NOOVERLAP    1
#define COFB_ENCRYPT 1		// 1 is encrypt , 0 is decrypt

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH 16000000	//64000

#define TAGBYTES        CRYPTO_ABYTES
#define BLOCKBYTES      CRYPTO_ABYTES

#define COFB_ENCRYPT    1		//encrypt 1 , decrypt 0
//#define PRINT
//#define PRINTC
#define BATCH_SIZE 5
#define fineLevel 4 //Change Fine Level to 4 / 8 / 16
//#ifdef WRITEFILE

typedef unsigned char block[16];
typedef unsigned char half_block[8];

//Optimisation PARAMS
typedef unsigned char u8;
typedef unsigned int u32;

#define U32BIG(x)											\
  ((((x) & 0x000000FF) << 24) | (((x) & 0x0000FF00) << 8) | \
   (((x) & 0x00FF0000) >> 8) | (((x) & 0xFF000000) >> 24))

#define U8BIG(x, y)											\
	(x)[0] = (y) >> 24; 									\
	(x)[1] = ((y) >> 16) & 0xff; 							\
	(x)[2] = ((y) >> 8) & 0xff; 							\
	(x)[3] = (y) & 0xff;

#define Tlimit 513

#define ROR(x,y)											\
	(((x) >> (y)) | ((x) << (32 - (y))))
#define BYTE_ROR_2(x)										\
	((((x) >> 2) & 0x3f3f3f3f)	| (((x) & 0x03030303) << 6))
#define BYTE_ROR_4(x) 										\
	((((x) >> 4) & 0x0f0f0f0f)	| (((x) & 0x0f0f0f0f) << 4))
#define BYTE_ROR_6(x) 										\
	((((x) >> 6) & 0x03030303)	| (((x) & 0x3f3f3f3f) << 2))
#define HALF_ROR_4(x) 										\
	((((x) >> 4) & 0x0fff0fff)	| (((x) & 0x000f000f) << 12))
#define HALF_ROR_8(x) 										\
	((((x) >> 8) & 0x00ff00ff)	| (((x) & 0x00ff00ff) << 8))
#define HALF_ROR_12(x) 										\
	((((x) >> 12)& 0x000f000f)	| (((x) & 0x0fff0fff) << 4))
#define NIBBLE_ROR_1(x)										\
	((((x) >> 1) & 0x77777777) 	| (((x) & 0x11111111) << 3))
#define NIBBLE_ROR_2(x)										\
	((((x) >> 2) & 0x33333333) 	| (((x) & 0x33333333) << 2))
#define NIBBLE_ROR_3(x)										\
	((((x) >> 3) & 0x11111111) 	| (((x) & 0x77777777) << 1))

#define SWAPMOVE(a, b, mask, n)								\
	tmp = (b ^ (a >> n)) & mask;							\
	b ^= tmp;												\
	a ^= (tmp << n);

#define SBOX(s0, s1, s2, s3)								\
	s1 ^= s0 & s2;											\
	s0 ^= s1 & s3;											\
	s2 ^= s0 | s1;											\
	s3 ^= s2;												\
	s1 ^= s3;												\
	s3 ^= 0xffffffff;										\
	s2 ^= s0 & s1;

#define KEY_UPDATE(x)											\
	(((x) >> 12) & 0x0000000f)	| (((x) & 0x00000fff) << 4) | 	\
	(((x) >> 2) & 0x3fff0000)	| (((x) & 0x00030000) << 14)

#define KEY_TRIPLE_UPDATE_0(x)									\
	(ROR((x) & 0x33333333, 24) 	| ROR((x) & 0xcccccccc, 16))

#define KEY_DOUBLE_UPDATE_1(x)									\
	((((x) >> 4) & 0x0f000f00)	| (((x) & 0x0f000f00) << 4) | 	\
	(((x) >> 6) & 0x00030003)	| (((x) & 0x003f003f) << 2))

#define KEY_TRIPLE_UPDATE_1(x)									\
	((((x) >> 6) & 0x03000300)	| (((x) & 0x3f003f00) << 2) | 	\
	(((x) >> 5) & 0x00070007)	| (((x) & 0x001f001f) << 3))

#define KEY_DOUBLE_UPDATE_2(x)									\
	(ROR((x) & 0xaaaaaaaa, 24)	| ROR((x) & 0x55555555, 16))

#define KEY_TRIPLE_UPDATE_2(x)									\
	(ROR((x) & 0x55555555, 24)	| ROR((x) & 0xaaaaaaaa, 20))

#define KEY_DOUBLE_UPDATE_3(x)									\
	((((x) >> 2) & 0x03030303)	| (((x) & 0x03030303) << 2) | 	\
	(((x) >> 1) & 0x70707070)	| (((x) & 0x10101010) << 3))

#define KEY_TRIPLE_UPDATE_3(x)									\
	((((x) >> 18) & 0x00003030)	| (((x) & 0x01010101) << 3) | 	\
	(((x) >> 14) & 0x0000c0c0)	| (((x) & 0x0000e0e0) << 15)|	\
	(((x) >> 1) & 0x07070707)	| (((x) & 0x00001010) << 19))

#define KEY_DOUBLE_UPDATE_4(x)									\
	((((x) >> 4)  & 0x0fff0000)	| (((x) & 0x000f0000) << 12) | 	\
	(((x) >> 8)  & 0x000000ff)	| (((x) & 0x000000ff) << 8))

#define KEY_TRIPLE_UPDATE_4(x)									\
	((((x) >> 6)  & 0x03ff0000)	| (((x) & 0x003f0000) << 10) |	\
	(((x) >> 4)  & 0x00000fff)	| (((x) & 0x0000000f) << 12))


#define QUINTUPLE_ROUND(state, rkey, rconst) 				\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = NIBBLE_ROR_1(state[3]);						\
	state[1] = NIBBLE_ROR_2(state[1]);						\
	state[2] = NIBBLE_ROR_3(state[2]);						\
	state[1] ^= (rkey)[0];									\
	state[2] ^= (rkey)[1];									\
	state[0] ^= (rconst)[0];								\
	SBOX(state[3], state[1], state[2], state[0]);			\
	state[0] = HALF_ROR_4(state[0]);						\
	state[1] = HALF_ROR_8(state[1]);						\
	state[2] = HALF_ROR_12(state[2]);						\
	state[1] ^= (rkey)[2];									\
	state[2] ^= (rkey)[3];									\
	state[3] ^= (rconst)[1];								\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = ROR(state[3], 16);							\
	state[2] = ROR(state[2], 16);							\
	SWAPMOVE(state[1], state[1], 0x55555555, 1);			\
	SWAPMOVE(state[2], state[2], 0x00005555, 1);			\
	SWAPMOVE(state[3], state[3], 0x55550000, 1);			\
	state[1] ^= (rkey)[4];									\
	state[2] ^= (rkey)[5];									\
	state[0] ^= (rconst)[2];								\
	SBOX(state[3], state[1], state[2], state[0]);			\
	state[0] = BYTE_ROR_6(state[0]);						\
	state[1] = BYTE_ROR_4(state[1]);						\
	state[2] = BYTE_ROR_2(state[2]);						\
	state[1] ^= (rkey)[6];									\
	state[2] ^= (rkey)[7];									\
	state[3] ^= (rconst)[3];								\
	SBOX(state[0], state[1], state[2], state[3]);			\
	state[3] = ROR(state[3], 24);							\
	state[1] = ROR(state[1], 16);							\
	state[2] = ROR(state[2], 8);							\
	state[1] ^= (rkey)[8];									\
	state[2] ^= (rkey)[9];									\
	state[0] ^= (rconst)[4];								\
	state[0] ^= state[3];									\
	state[3] ^= state[0];									\
	state[0] ^= state[3];									


#define DOUBLE_HALF_BLOCK(x)                                              \
	tmp0 = (x)[0];                                                          \
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);  \
    (x)[0] |= ((x)[1] & 0x80808080) << 17;                                  \
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);  \
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;                               


#define TRIPLE_HALF_BLOCK(x)                                              \
	tmp0 = (x)[0];															\
	tmp1 = (x)[1];															\
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);	\
    (x)[0] |= ((x)[1] & 0x80808080) << 17;									\
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);	\
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;								\
    (x)[0] ^= tmp0;															\
    (x)[1] ^= tmp1;															


#define G(x)                                                              \
	tmp0 = (x)[0];                                                          \
	tmp1 = (x)[1];                                                          \
	(x)[0] = (x)[2];														\
	(x)[1] = (x)[3];														\
    (x)[2] = ((tmp0 & 0x7f7f7f7f) << 1) | ((tmp0 & 0x80808080) >> 15);      \
    (x)[2] |= ((tmp1 & 0x80808080) << 17);								    \
    (x)[3] = ((tmp1 & 0x7f7f7f7f) << 1) | ((tmp1 & 0x80808080) >> 15);      \
    (x)[3] |= ((tmp0 & 0x80808080) << 17);									


#define XOR_BLOCK(x, y, z)        \
    (x)[0] = (y)[0] ^ (z)[0];       \
    (x)[1] = (y)[1] ^ (z)[1];       \
    (x)[2] = (y)[2] ^ (z)[2];       \
    (x)[3] = (y)[3] ^ (z)[3];       


#define XOR_TOP_BAR_BLOCK(x, y)  \
    (x)[0] ^= (y)[0];               \
    (x)[1] ^= (y)[1];               

/*
#define RHO1C(d, y, m, n)          \
	G(y);                           \
	paddingC(d,m,n);                 \
	XOR_BLOCK(d, d, y);


#define RHO1G(d, y, m, n)          \
	G(y);                           \
	paddingG_Op(d,m,n);                 \
	XOR_BLOCK(d, d, y);   */


	//#define RHO(y, m, x, c, n) ({       \
	//    XOR_BLOCK(c, y, m);				\
	//    RHO1(x, y, m, n);				\
	//})
	//
	//#define RHO_PRIME(y, c, x, m, n) ({ \
	//    XOR_BLOCK(m, y, c);             \
	//    RHO1(x, y, m, n);               \
	//})


#define REARRANGE_RKEY_0(x) 			\
	SWAPMOVE(x, x, 0x00550055, 9);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		

#define REARRANGE_RKEY_1(x) 			\
	SWAPMOVE(x, x, 0x11111111, 3);		\
	SWAPMOVE(x, x, 0x03030303, 6);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		


#define REARRANGE_RKEY_2(x) 			\
	SWAPMOVE(x, x, 0x0000aaaa, 15);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		

#define REARRANGE_RKEY_3(x) 			\
	SWAPMOVE(x, x, 0x0a0a0a0a, 3);		\
	SWAPMOVE(x, x, 0x00cc00cc, 6);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		






#define REARRANGE_RKEY_0T(x,y) 			\
	SWAPMOVE(x, x, 0x00550055, 9);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
	(y) = (x)

#define REARRANGE_RKEY_1T(x,y) 			\
	SWAPMOVE(x, x, 0x11111111, 3);		\
	SWAPMOVE(x, x, 0x03030303, 6);		\
	SWAPMOVE(x, x, 0x000f000f, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
	(y) = (x)

#define REARRANGE_RKEY_2T(x,y) 			\
	SWAPMOVE(x, x, 0x0000aaaa, 15);		\
	SWAPMOVE(x, x, 0x00003333, 18);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
	(y) = (x)

#define REARRANGE_RKEY_3T(x,y) 			\
	SWAPMOVE(x, x, 0x0a0a0a0a, 3);		\
	SWAPMOVE(x, x, 0x00cc00cc, 6);		\
	SWAPMOVE(x, x, 0x0000f0f0, 12);		\
	SWAPMOVE(x, x, 0x000000ff, 24);		\
	(y) = (x)

#define giftb128G_OpT(ctext, ptext)	\
	state[0] = U32BIG(((u32*)ptext)[0]);	\
	state[1] = U32BIG(((u32*)ptext)[1]);	\
	state[2] = U32BIG(((u32*)ptext)[2]);	\
	state[3] = U32BIG(((u32*)ptext)[3]);	\
	QUINTUPLE_ROUND(state, rkey, rconstG_Op + 0);			\
	QUINTUPLE_ROUND(state, rkey + 10, rconstG_Op + 5);		\
	QUINTUPLE_ROUND(state, rkey + 20, rconstG_Op + 10);		\
	QUINTUPLE_ROUND(state, rkey + 30, rconstG_Op + 15);		\
	QUINTUPLE_ROUND(state, rkey + 40, rconstG_Op + 20);		\
	QUINTUPLE_ROUND(state, rkey + 50, rconstG_Op + 25);		\
	QUINTUPLE_ROUND(state, rkey + 60, rconstG_Op + 30);		\
	QUINTUPLE_ROUND(state, rkey + 70, rconstG_Op + 35);		\
	U8BIG(ctext, state[0]);			\
	U8BIG(ctext + 4, state[1]);		\
	U8BIG(ctext + 8, state[2]);		\
	U8BIG(ctext + 12, state[3]);







/*****************************************************************************
* Optimised Version
*****************************************************************************/
#define QUINTUPLE_ROUND_Op(rkey, rconst) 				\
	SBOX(s0,s1,s2,s3);			\
	s3 = NIBBLE_ROR_1(s3);						\
	s1 = NIBBLE_ROR_2(s1);						\
	s2 = NIBBLE_ROR_3(s2);						\
	s1 ^= (rkey)[0];									\
	s2 ^= (rkey)[1];									\
	s0 ^= (rconst)[0];								\
	SBOX(s3,s1,s2,s0);			\
	s0 = HALF_ROR_4(s0);						\
	s1 = HALF_ROR_8(s1);						\
	s2 = HALF_ROR_12(s2);						\
	s1 ^= (rkey)[2];									\
	s2 ^= (rkey)[3];									\
	s3 ^= (rconst)[1];								\
	SBOX(s0,s1,s2,s3);			\
	s3 = ROR(s3, 16);							\
	s2 = ROR(s2, 16);							\
	SWAPMOVE(s1,s1, 0x55555555, 1);			\
	SWAPMOVE(s2,s2, 0x00005555, 1);			\
	SWAPMOVE(s3,s3, 0x55550000, 1);			\
	s1 ^= (rkey)[4];									\
	s2 ^= (rkey)[5];									\
	s0 ^= (rconst)[2];								\
	SBOX(s3,s1,s2,s0);			\
	s0 = BYTE_ROR_6(s0);						\
	s1= BYTE_ROR_4(s1);						\
	s2 = BYTE_ROR_2(s2);						\
	s1 ^= (rkey)[6];									\
	s2 ^= (rkey)[7];									\
	s3 ^= (rconst)[3];								\
	SBOX(s0,s1,s2,s3);			\
	s3 = ROR(s3, 24);							\
	s1 = ROR(s1, 16);							\
	s2 = ROR(s2, 8);							\
	s1 ^= (rkey)[8];									\
	s2 ^= (rkey)[9];									\
	s0 ^= (rconst)[4];								\
	s0 ^= s3;									\
	s3 ^= s0;									\
	s0 ^= s3;									