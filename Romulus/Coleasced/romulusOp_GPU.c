/*
 * Date: 29 November 2018
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 * Mustafa Khairallah - mustafam001@e.ntu.edu.sg
 */

#include "params.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

 ///////////////// Romulus M - Op32 Ref ///////////
/*
 * S-BOX
 */
__device__ unsigned char SBOXG[]
= {
	// Original
	0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
	0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
	0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
	0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
	0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
	0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
	0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
	0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
	0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
	0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
	0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
	0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
	0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
	0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
	0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
	0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,
};

/*
* S-BOX ^ AC(c2)
*/
__device__ unsigned char SBOXG2[]
= {   // Original ^ c2(0x02)
	0x67, 0x4e, 0x68, 0x40, 0x49, 0x61, 0x41, 0x69, 0x57, 0x77, 0x58, 0x78, 0x51, 0x71, 0x59, 0x79,
	0x37, 0x8e, 0x38, 0x83, 0x8b, 0x31, 0x82, 0x39, 0x97, 0x27, 0x9a, 0x28, 0x92, 0x21, 0x9b, 0x29,
	0xe7, 0xce, 0xea, 0xc3, 0xcb, 0xe2, 0xc2, 0xeb, 0xd7, 0xf7, 0xda, 0xfa, 0xd2, 0xf2, 0xdb, 0xfb,
	0xa7, 0x1e, 0xaa, 0x10, 0x19, 0xa2, 0x11, 0xab, 0x07, 0xb7, 0x08, 0xba, 0x01, 0xb2, 0x09, 0xbb,
	0x30, 0x8a, 0x3e, 0x87, 0x8f, 0x36, 0x86, 0x3f, 0x93, 0x20, 0x9e, 0x2e, 0x96, 0x26, 0x9f, 0x2f,
	0x60, 0x48, 0x6e, 0x47, 0x4f, 0x66, 0x46, 0x6f, 0x50, 0x70, 0x5e, 0x7e, 0x56, 0x76, 0x5f, 0x7f,
	0xa3, 0x18, 0xae, 0x17, 0x1f, 0xa6, 0x16, 0xaf, 0x00, 0xb3, 0x0e, 0xbe, 0x06, 0xb6, 0x0f, 0xbf,
	0xe3, 0xca, 0xee, 0xc7, 0xcf, 0xe6, 0xc6, 0xef, 0xd3, 0xf3, 0xde, 0xfe, 0xd6, 0xf6, 0xdf, 0xff,
	0x34, 0x8c, 0x3a, 0x80, 0x89, 0x32, 0x81, 0x3b, 0x94, 0x24, 0x98, 0x2a, 0x91, 0x22, 0x99, 0x2b,
	0x64, 0x4c, 0x6a, 0x43, 0x4b, 0x62, 0x42, 0x6b, 0x54, 0x74, 0x5a, 0x7a, 0x52, 0x72, 0x5b, 0x7b,
	0xa4, 0x1c, 0xa8, 0x13, 0x1b, 0xa1, 0x12, 0xa9, 0x04, 0xb4, 0x0a, 0xb8, 0x02, 0xb1, 0x0b, 0xb9,
	0xe4, 0xcc, 0xe8, 0xc0, 0xc9, 0xe1, 0xc1, 0xe9, 0xd4, 0xf4, 0xd8, 0xf8, 0xd1, 0xf1, 0xd9, 0xf9,
	0x33, 0x88, 0x3c, 0x84, 0x8d, 0x35, 0x85, 0x3d, 0x90, 0x23, 0x9c, 0x2c, 0x95, 0x25, 0x9d, 0x2d,
	0x63, 0x4a, 0x6c, 0x44, 0x4d, 0x65, 0x45, 0x6d, 0x53, 0x73, 0x5c, 0x7c, 0x55, 0x75, 0x5d, 0x7d,
	0xa0, 0x1a, 0xac, 0x14, 0x1d, 0xa5, 0x15, 0xad, 0x03, 0xb0, 0x0c, 0xbc, 0x05, 0xb5, 0x0d, 0xbd,
	0xe0, 0xc8, 0xec, 0xc4, 0xcd, 0xe5, 0xc5, 0xed, 0xd0, 0xf0, 0xdc, 0xfc, 0xd5, 0xf5, 0xdd, 0xfd,
};


#ifdef ___SKINNY_LOOP

__device__ extern void RunEncryptionKeyScheduleTK3G(uint32_t* roundKeys, unsigned char* pRC);

/*
 * Round Constants
 */
__device__ unsigned char RCOG[]
= {
	0x01, 0x00, 0x03, 0x00, 0x07, 0x00, 0x0f, 0x00, 0x0f, 0x01, 0x0e, 0x03, 0x0d, 0x03, 0x0b, 0x03,
	0x07, 0x03, 0x0f, 0x02, 0x0e, 0x01, 0x0c, 0x03, 0x09, 0x03, 0x03, 0x03, 0x07, 0x02, 0x0e, 0x00,
	0x0d, 0x01, 0x0a, 0x03, 0x05, 0x03, 0x0b, 0x02, 0x06, 0x01, 0x0c, 0x02, 0x08, 0x01, 0x00, 0x03,
	0x01, 0x02, 0x02, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x07, 0x01, 0x0e, 0x02, 0x0c, 0x01, 0x08, 0x03,
	0x01, 0x03, 0x03, 0x02, 0x06, 0x00, 0x0d, 0x00, 0x0b, 0x01, 0x06, 0x03, 0x0d, 0x02, 0x0a, 0x01,

};

__device__ void RunEncryptionKeyScheduleTK2G(uint32_t* roundKeys)
{
	uint32_t* tk2;  // used in MACRO
	uint32_t* tk3;  // used in MACRO
	uint32_t t0;    // used in MACRO
	uint32_t t1;    // used in MACRO
	uint32_t t2;    // used in MACRO
	uint32_t w0;
	uint32_t w1;

	// odd

	// load master key
	w0 = roundKeys[4];
	w1 = roundKeys[5];

	tk2 = &roundKeys[16];
#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[96];
#else
	tk3 = &roundKeys[128];
#endif

	// 1st round
	* tk2++ = w0 ^ *tk3++;
	*tk2++ = w1 ^ *tk3++;

	tk2 += 2;
	tk3 += 2;

	// 3rd,5th, ...
#ifndef ___NUM_OF_ROUNDS_56
	for (int i = 0; i < 19; i++)
#else
	for (int i = 0; i < 27; i++)
#endif
	{
		PERMUTATION_TK2();
	}

	// even

	// load master key
	w0 = roundKeys[6];
	w1 = roundKeys[7];

	tk2 = &roundKeys[18];
#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[98];
#else
	tk3 = &roundKeys[130];
#endif

	// 2nd,4th, ...
#ifndef ___NUM_OF_ROUNDS_56
	for (int i = 0; i < 20; i++)
#else
	for (int i = 0; i < 28; i++)
#endif
	{
		PERMUTATION_TK2();
	}

}

__device__ void RunEncryptionKeyScheduleTK3G(uint32_t* roundKeys, unsigned char* pRC)
{
	uint32_t* tk3;
	uint32_t t0;         // used in MACRO
	uint32_t t1;         // used in MACRO
	uint32_t t2;         // used in MACRO
	uint32_t w0;
	uint32_t w1;
	uint16_t c0;
	uint16_t c1;

	// odd
	// load master key
	w0 = roundKeys[8];
	w1 = roundKeys[9];

#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[96];
#else
	tk3 = &roundKeys[128];
#endif

	// 1st round
	* tk3++ = w0 ^ 0x01;
	*tk3++ = w1;
	tk3 += 2;

	pRC += 4;
	// 3rd,5th, ...
#ifndef ___NUM_OF_ROUNDS_56
	for (int i = 0; i < 19; i++)
#else
	for (int i = 0; i < 27; i++)
#endif
	{
		c0 = *pRC++;
		c1 = *pRC++;
		c1 <<= 8;
		pRC += 2;
		PERMUTATION_TK3(c0, c1);
	}

	// even

	// load master key
	w0 = roundKeys[10];
	w1 = roundKeys[11];

#ifndef ___NUM_OF_ROUNDS_56
	pRC -= 78;
	tk3 = &roundKeys[98];
#else
	pRC -= 110;
	tk3 = &roundKeys[130];
#endif

	// 2nd,4th, ...
#ifndef ___NUM_OF_ROUNDS_56
	for (int i = 0; i < 20; i++)
#else
	for (int i = 0; i < 28; i++)
#endif
	{
		c0 = *pRC++;
		c1 = *pRC++;
		c1 <<= 8;
		pRC += 2;
		PERMUTATION_TK3(c0, c1);
	}

}

__device__ void EncryptG(unsigned char* block, uint32_t* roundKeys, unsigned char* sboxG, unsigned char* sbox2G)
{
	uint32_t* tk1;
	uint32_t* tk2;
	uint32_t t0;          // used in MACRO
	uint32_t t1;          // used in MACRO
	uint32_t t2;          // used in MACRO
	uint32_t t3;          // used in MACRO
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;

	// TK1

	  // load master key
	w0 = roundKeys[0];
	w1 = roundKeys[1];

	// 1st round
	// not need to store

	tk1 = &roundKeys[2];

	// 2nd, ... ,8th round
	for (int i = 0; i < 7; i++)
	{
		PERMUTATION_TK1();
	}

	// SB+AC+ShR+MC

#ifndef ___ENABLE_WORD_CAST
	pack_word(block[0], block[1], block[2], block[3], w0);
	pack_word(block[4], block[5], block[6], block[7], w1);
	pack_word(block[8], block[9], block[10], block[11], w2);
	pack_word(block[12], block[13], block[14], block[15], w3);
#else
	w0 = *(uint32_t*)(&block[0]);
	w1 = *(uint32_t*)(&block[4]);
	w2 = *(uint32_t*)(&block[8]);
	w3 = *(uint32_t*)(&block[12]);
#endif

	tk2 = &roundKeys[16];

	// 1st, ... ,32th or 48th round
#ifndef ___NUM_OF_ROUNDS_56
	for (int j = 0; j < 2; j++)
#else
	for (int j = 0; j < 3; j++)
#endif
	{
		tk1 = &roundKeys[0];
		for (int i = 0; i < 8; i++)
		{
			SKINNY_MAING();
		}
	}

	// 33th , ... ,40th or 49th, .... ,56th round
	{
		tk1 = &roundKeys[0];
		for (int i = 0; i < 4; i++)
		{
			SKINNY_MAING();
		}
	}
#ifndef ___ENABLE_WORD_CAST
	unpack_word(block[0], block[1], block[2], block[3], w0);
	unpack_word(block[4], block[5], block[6], block[7], w1);
	unpack_word(block[8], block[9], block[10], block[11], w2);
	unpack_word(block[12], block[13], block[14], block[15], w3);
#else
	* (uint32_t*)(&block[0]) = w0;
	*(uint32_t*)(&block[4]) = w1;
	*(uint32_t*)(&block[8]) = w2;
	*(uint32_t*)(&block[12]) = w3;
#endif

}


#else

extern void RunEncryptionKeyScheduleTK3(uint32_t* roundKeys);


#ifdef ___NUM_OF_ROUNDS_56
0x04, 0x03, 0x09, 0x02, 0x02, 0x01, 0x04, 0x02, 0x08, 0x00, 0x01, 0x01, 0x02, 0x02, 0x04, 0x00,
0x09, 0x00, 0x03, 0x01, 0x06, 0x02, 0x0c, 0x00, 0x09, 0x01, 0x02, 0x03, 0x05, 0x02, 0x0a, 0x00,
#endif

void RunEncryptionKeyScheduleTK2(uint32_t* roundKeys)
{
	uint32_t* tk2;  // used in MACRO
	uint32_t* tk3;  // used in MACRO
	uint32_t t0;    // used in MACRO
	uint32_t t1;    // used in MACRO
	uint32_t t2;    // used in MACRO
	uint32_t w0;
	uint32_t w1;

	// odd

	// load master key
	w0 = roundKeys[4];
	w1 = roundKeys[5];

	tk2 = &roundKeys[16];
#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[96];
#else
	tk3 = &roundKeys[128];
#endif

	// 1st round
	* tk2++ = w0 ^ *tk3++;
	*tk2++ = w1 ^ *tk3++;

	tk2 += 2;
	tk3 += 2;

	// 3rd,5th, ... ,37th,39th round
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

#ifdef ___NUM_OF_ROUNDS_56

	// 41th,43th, ... ,51th,53th round
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

#endif

	// even

	// load master key
	w0 = roundKeys[6];
	w1 = roundKeys[7];

	tk2 = &roundKeys[18];
#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[98];
#else
	tk3 = &roundKeys[130];
#endif

	// 2nd,4th, ... ,54th,56th round
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

#ifdef ___NUM_OF_ROUNDS_56

	// 42nd,44th, ... ,54th,56th round
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();
	PERMUTATION_TK2();

#endif

}

void RunEncryptionKeyScheduleTK3(uint32_t* roundKeys)
{
	uint32_t* tk3;
	uint32_t t0;         // used in MACRO
	uint32_t t1;         // used in MACRO
	uint32_t t2;         // used in MACRO
	uint32_t w0;
	uint32_t w1;

	// odd

	// load master key
	w0 = roundKeys[8];
	w1 = roundKeys[9];

#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[96];
#else
	tk3 = &roundKeys[128];
#endif

	// 1st round
	* tk3++ = w0 ^ 0x01;
	*tk3++ = w1;
	tk3 += 2;

	// 3rd,5th, ... ,37th,39th round
	PERMUTATION_TK3(0x7, 0x000);
	PERMUTATION_TK3(0xf, 0x100);
	PERMUTATION_TK3(0xd, 0x300);
	PERMUTATION_TK3(0x7, 0x300);
	PERMUTATION_TK3(0xe, 0x100);
	PERMUTATION_TK3(0x9, 0x300);
	PERMUTATION_TK3(0x7, 0x200);
	PERMUTATION_TK3(0xd, 0x100);
	PERMUTATION_TK3(0x5, 0x300);

	PERMUTATION_TK3(0x6, 0x100);
	PERMUTATION_TK3(0x8, 0x100);
	PERMUTATION_TK3(0x1, 0x200);
	PERMUTATION_TK3(0x5, 0x000);
	PERMUTATION_TK3(0x7, 0x100);
	PERMUTATION_TK3(0xc, 0x100);
	PERMUTATION_TK3(0x1, 0x300);
	PERMUTATION_TK3(0x6, 0x000);
	PERMUTATION_TK3(0xb, 0x100);
	PERMUTATION_TK3(0xd, 0x200);

#ifdef ___NUM_OF_ROUNDS_56

	// 41td,43th, ... ,53th,55th round
	PERMUTATION_TK3(0x4, 0x300);
	PERMUTATION_TK3(0x2, 0x100);
	PERMUTATION_TK3(0x8, 0x000);
	PERMUTATION_TK3(0x2, 0x200);
	PERMUTATION_TK3(0x9, 0x000);
	PERMUTATION_TK3(0x6, 0x200);
	PERMUTATION_TK3(0x9, 0x100);
	PERMUTATION_TK3(0x5, 0x200);

#endif

	// even

	// load master key
	w0 = roundKeys[10];
	w1 = roundKeys[11];


#ifndef ___NUM_OF_ROUNDS_56
	tk3 = &roundKeys[98];
#else
	tk3 = &roundKeys[130];
#endif

	// 2nd,4th, ... ,38th,40th round
	PERMUTATION_TK3(0x3, 0x000);
	PERMUTATION_TK3(0xf, 0x000);
	PERMUTATION_TK3(0xe, 0x300);
	PERMUTATION_TK3(0xb, 0x300);
	PERMUTATION_TK3(0xf, 0x200);
	PERMUTATION_TK3(0xc, 0x300);
	PERMUTATION_TK3(0x3, 0x300);
	PERMUTATION_TK3(0xe, 0x000);
	PERMUTATION_TK3(0xa, 0x300);
	PERMUTATION_TK3(0xb, 0x200);

	PERMUTATION_TK3(0xc, 0x200);
	PERMUTATION_TK3(0x0, 0x300);
	PERMUTATION_TK3(0x2, 0x000);
	PERMUTATION_TK3(0xb, 0x000);
	PERMUTATION_TK3(0xe, 0x200);
	PERMUTATION_TK3(0x8, 0x300);
	PERMUTATION_TK3(0x3, 0x200);
	PERMUTATION_TK3(0xd, 0x000);
	PERMUTATION_TK3(0x6, 0x300);
	PERMUTATION_TK3(0xa, 0x100);

#ifdef ___NUM_OF_ROUNDS_56

	// 42nd,44th, ... ,54th,56th round
	PERMUTATION_TK3(0x9, 0x200);
	PERMUTATION_TK3(0x4, 0x200);
	PERMUTATION_TK3(0x1, 0x100);
	PERMUTATION_TK3(0x4, 0x000);
	PERMUTATION_TK3(0x3, 0x100);
	PERMUTATION_TK3(0xc, 0x000);
	PERMUTATION_TK3(0x2, 0x300);
	PERMUTATION_TK3(0xa, 0x000);

#endif

}


void Encrypt(unsigned char* block, uint32_t* roundKeys, unsigned char* SBOXG, unsigned char* SBOXG2)
{
	uint32_t* tk1;
	uint32_t* tk2;
	uint32_t t0;          // used in MACRO
	uint32_t t1;          // used in MACRO
	uint32_t t2;          // used in MACRO
	uint32_t t3;          // used in MACRO
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;

	// TK1

	  // load master key
	w0 = roundKeys[0];
	w1 = roundKeys[1];

	// 1st round
	// not need to store

	tk1 = &roundKeys[2];

	// 2nd, ... ,8th round
	PERMUTATION_TK1();
	PERMUTATION_TK1();
	PERMUTATION_TK1();
	PERMUTATION_TK1();
	PERMUTATION_TK1();
	PERMUTATION_TK1();
	PERMUTATION_TK1();

	// SB+AC+ShR+MC

#ifndef ___ENABLE_WORD_CAST
	pack_word(block[0], block[1], block[2], block[3], w0);
	pack_word(block[4], block[5], block[6], block[7], w1);
	pack_word(block[8], block[9], block[10], block[11], w2);
	pack_word(block[12], block[13], block[14], block[15], w3);
#else
	w0 = *(uint32_t*)(&block[0]);
	w1 = *(uint32_t*)(&block[4]);
	w2 = *(uint32_t*)(&block[8]);
	w3 = *(uint32_t*)(&block[12]);
#endif

	tk2 = &roundKeys[16];
	tk1 = &roundKeys[0];

	// 1st, ...,16th round
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();

	tk1 = &roundKeys[0];

	// 17th, ...,32th round
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();

	tk1 = &roundKeys[0];

	// 33th, ...,40th round
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();

#ifdef ___NUM_OF_ROUNDS_56

	// 41th, ...,48th round
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();

	tk1 = &roundKeys[0];

	// 49th, ... ,56th round
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();
	SKINNY_MAIN();

#endif

#ifndef ___ENABLE_WORD_CAST
	unpack_word(block[0], block[1], block[2], block[3], w0);
	unpack_word(block[4], block[5], block[6], block[7], w1);
	unpack_word(block[8], block[9], block[10], block[11], w2);
	unpack_word(block[12], block[13], block[14], block[15], w3);
#else
	* (uint32_t*)(&block[0]) = w0;
	*(uint32_t*)(&block[4]) = w1;
	*(uint32_t*)(&block[8]) = w2;
	*(uint32_t*)(&block[12]) = w3;
#endif

}

#endif

__device__ void skinny_128_384_enc123_12G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pack_word(T[0], T[1], T[2], T[3], pt[4]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pack_word(T[8], T[9], T[10], T[11], pt[6]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);

	pack_word(K[0], K[1], K[2], K[3], pt[8]);
	pack_word(K[7], K[4], K[5], K[6], pt[9]);
	pack_word(K[8], K[9], K[10], K[11], pt[10]);
	pack_word(K[15], K[12], K[13], K[14], pt[11]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pt[4] = *(uint32_t*)(&T[0]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pt[6] = *(uint32_t*)(&T[8]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);

	pt[8] = *(uint32_t*)(&K[0]);
	pack_word(K[7], K[4], K[5], K[6], pt[9]);
	pt[10] = *(uint32_t*)(&K[8]);
	pack_word(K[15], K[12], K[13], K[14], pt[11]);
#endif

#ifdef ___SKINNY_LOOP
	RunEncryptionKeyScheduleTK3G(pskinny_ctrl->roundKeys, RCOG);
#else
	RunEncryptionKeyScheduleTK3G(pskinny_ctrl->roundKeys);
#endif
	RunEncryptionKeyScheduleTK2G(pskinny_ctrl->roundKeys);
	EncryptG(input, pskinny_ctrl->roundKeys, SBOXG, SBOXG2);

	pskinny_ctrl->func_skinny_128_384_enc = skinny_128_384_enc12_12G;

}

__device__ void skinny_128_384_enc12_12G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	(void)K;

	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pack_word(T[0], T[1], T[2], T[3], pt[4]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pack_word(T[8], T[9], T[10], T[11], pt[6]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pt[4] = *(uint32_t*)(&T[0]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pt[6] = *(uint32_t*)(&T[8]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);
#endif

	RunEncryptionKeyScheduleTK2G(pskinny_ctrl->roundKeys);
	EncryptG(input, pskinny_ctrl->roundKeys, SBOXG, SBOXG2);

}

__device__ extern void skinny_128_384_enc1_1G(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	(void)T;
	(void)K;

	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#endif

	EncryptG(input, pskinny_ctrl->roundKeys, SBOXG, SBOXG2);

}


__device__ void padOG(const unsigned char* m, unsigned char* mp, int len8) {

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&mp[0]) = 0;
	*(uint32_t*)(&mp[4]) = 0;
	*(uint32_t*)(&mp[8]) = 0;
	*(uint32_t*)(&mp[12]) = 0;
	mp[15] = (len8 & 0x0f);
	for (int i = 0; i < len8; i++) {
		mp[i] = m[i];
	}

#else

	mp[0] = 0;
	mp[1] = 0;
	mp[2] = 0;
	mp[3] = 0;
	mp[4] = 0;
	mp[5] = 0;
	mp[6] = 0;
	mp[7] = 0;
	mp[8] = 0;
	mp[9] = 0;
	mp[10] = 0;
	mp[11] = 0;
	mp[12] = 0;
	mp[13] = 0;
	mp[14] = 0;
	mp[15] = (len8 & 0x0f);
	for (int i = 0; i < len8; i++) {
		mp[i] = m[i];
	}

#endif

}

__device__ void g8AOG(unsigned char* s, unsigned char* c) {

#ifdef ___ENABLE_WORD_CAST

	uint32_t s0 = *(uint32_t*)(&s[0]);
	uint32_t s1 = *(uint32_t*)(&s[4]);
	uint32_t s2 = *(uint32_t*)(&s[8]);
	uint32_t s3 = *(uint32_t*)(&s[12]);

	uint32_t c0, c1, c2, c3;

	c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
	c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
	c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
	c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

	*(uint32_t*)(&c[0]) = c0;
	*(uint32_t*)(&c[4]) = c1;
	*(uint32_t*)(&c[8]) = c2;
	*(uint32_t*)(&c[12]) = c3;

#else

	uint32_t s0, s1, s2, s3;
	uint32_t c0, c1, c2, c3;

	pack_word(s[0], s[1], s[2], s[3], s0);
	pack_word(s[4], s[5], s[6], s[7], s1);
	pack_word(s[8], s[9], s[10], s[11], s2);
	pack_word(s[12], s[13], s[14], s[15], s3);

	c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
	c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
	c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
	c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

	unpack_word(c[0], c[1], c[2], c[3], c0);
	unpack_word(c[4], c[5], c[6], c[7], c1);
	unpack_word(c[8], c[9], c[10], c[11], c2);
	unpack_word(c[12], c[13], c[14], c[15], c3);

#endif

}

#ifdef ___ENABLE_WORD_CAST

__device__ void g8A_for_Tag_GenerationG(unsigned char* s, unsigned char* c) {

	uint32_t s0 = *(uint32_t*)(&s[0]);
	uint32_t s1 = *(uint32_t*)(&s[4]);
	uint32_t s2 = *(uint32_t*)(&s[8]);
	uint32_t s3 = *(uint32_t*)(&s[12]);

	uint32_t c0, c1, c2, c3;

	c0 = ((s0 >> 1) & 0x7f7f7f7f) ^ ((s0 ^ (s0 << 7)) & 0x80808080);
	c1 = ((s1 >> 1) & 0x7f7f7f7f) ^ ((s1 ^ (s1 << 7)) & 0x80808080);
	c2 = ((s2 >> 1) & 0x7f7f7f7f) ^ ((s2 ^ (s2 << 7)) & 0x80808080);
	c3 = ((s3 >> 1) & 0x7f7f7f7f) ^ ((s3 ^ (s3 << 7)) & 0x80808080);

	// use byte access because of memory alignment.
	// c is not always in word(4 byte) alignment.
	c[0] = c0 & 0xFF;
	c[1] = (c0 >> 8) & 0xFF;
	c[2] = (c0 >> 16) & 0xFF;
	c[3] = c0 >> 24;
	c[4] = c1 & 0xFF;
	c[5] = (c1 >> 8) & 0xFF;
	c[6] = (c1 >> 16) & 0xFF;
	c[7] = c1 >> 24;
	c[8] = c2 & 0xFF;
	c[9] = (c2 >> 8) & 0xFF;
	c[10] = (c2 >> 16) & 0xFF;
	c[11] = c2 >> 24;
	c[12] = c3 & 0xFF;
	c[13] = (c3 >> 8) & 0xFF;
	c[14] = (c3 >> 16) & 0xFF;
	c[15] = c3 >> 24;

}

#endif

#define rho_ad_eqov16_macro(i) \
  s[i] = s[i] ^ m[i];

__device__ void rho_ad_eqov16G(
	const unsigned char* m,
	unsigned char* s) {

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) ^= *(uint32_t*)(&m[0]);
	*(uint32_t*)(&s[4]) ^= *(uint32_t*)(&m[4]);
	*(uint32_t*)(&s[8]) ^= *(uint32_t*)(&m[8]);
	*(uint32_t*)(&s[12]) ^= *(uint32_t*)(&m[12]);

#else

	rho_ad_eqov16_macro(0);
	rho_ad_eqov16_macro(1);
	rho_ad_eqov16_macro(2);
	rho_ad_eqov16_macro(3);
	rho_ad_eqov16_macro(4);
	rho_ad_eqov16_macro(5);
	rho_ad_eqov16_macro(6);
	rho_ad_eqov16_macro(7);
	rho_ad_eqov16_macro(8);
	rho_ad_eqov16_macro(9);
	rho_ad_eqov16_macro(10);
	rho_ad_eqov16_macro(11);
	rho_ad_eqov16_macro(12);
	rho_ad_eqov16_macro(13);
	rho_ad_eqov16_macro(14);
	rho_ad_eqov16_macro(15);

#endif

}


__device__ void rho_ad_ud16G(
	const unsigned char* m,
	unsigned char* s,
	int len8) {

	unsigned char mp[16];
	padOG(m, mp, len8);

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) ^= *(uint32_t*)(&mp[0]);
	*(uint32_t*)(&s[4]) ^= *(uint32_t*)(&mp[4]);
	*(uint32_t*)(&s[8]) ^= *(uint32_t*)(&mp[8]);
	*(uint32_t*)(&s[12]) ^= *(uint32_t*)(&mp[12]);

#else

	rho_ad_ud16_macro(0);
	rho_ad_ud16_macro(1);
	rho_ad_ud16_macro(2);
	rho_ad_ud16_macro(3);
	rho_ad_ud16_macro(4);
	rho_ad_ud16_macro(5);
	rho_ad_ud16_macro(6);
	rho_ad_ud16_macro(7);
	rho_ad_ud16_macro(8);
	rho_ad_ud16_macro(9);
	rho_ad_ud16_macro(10);
	rho_ad_ud16_macro(11);
	rho_ad_ud16_macro(12);
	rho_ad_ud16_macro(13);
	rho_ad_ud16_macro(14);
	rho_ad_ud16_macro(15);

#endif

}

__device__ void rho_eqov16G(
	const unsigned char* m,
	unsigned char* c,
	unsigned char* s) {

	g8AOG(s, c);

#ifdef ___ENABLE_WORD_CAST

	uint32_t c0 = *(uint32_t*)(&c[0]);
	uint32_t c1 = *(uint32_t*)(&c[4]);
	uint32_t c2 = *(uint32_t*)(&c[8]);
	uint32_t c3 = *(uint32_t*)(&c[12]);

	uint32_t s0 = *(uint32_t*)(&s[0]);
	uint32_t s1 = *(uint32_t*)(&s[4]);
	uint32_t s2 = *(uint32_t*)(&s[8]);
	uint32_t s3 = *(uint32_t*)(&s[12]);

	uint32_t m0 = *(uint32_t*)(&m[0]);
	uint32_t m1 = *(uint32_t*)(&m[4]);
	uint32_t m2 = *(uint32_t*)(&m[8]);
	uint32_t m3 = *(uint32_t*)(&m[12]);

	s0 ^= m0;
	s1 ^= m1;
	s2 ^= m2;
	s3 ^= m3;

	c0 ^= m0;
	c1 ^= m1;
	c2 ^= m2;
	c3 ^= m3;

	*(uint32_t*)(&s[0]) = s0;
	*(uint32_t*)(&s[4]) = s1;
	*(uint32_t*)(&s[8]) = s2;
	*(uint32_t*)(&s[12]) = s3;

	*(uint32_t*)(&c[0]) = c0;
	*(uint32_t*)(&c[4]) = c1;
	*(uint32_t*)(&c[8]) = c2;
	*(uint32_t*)(&c[12]) = c3;

#else

	uint32_t c0, c1, c2, c3;
	uint32_t s0, s1, s2, s3;
	uint32_t m0, m1, m2, m3;

	pack_word(m[0], m[1], m[2], m[3], m0);
	pack_word(m[4], m[5], m[6], m[7], m1);
	pack_word(m[8], m[9], m[10], m[11], m2);
	pack_word(m[12], m[13], m[14], m[15], m3);

	pack_word(s[0], s[1], s[2], s[3], s0);
	pack_word(s[4], s[5], s[6], s[7], s1);
	pack_word(s[8], s[9], s[10], s[11], s2);
	pack_word(s[12], s[13], s[14], s[15], s3);

	pack_word(c[0], c[1], c[2], c[3], c0);
	pack_word(c[4], c[5], c[6], c[7], c1);
	pack_word(c[8], c[9], c[10], c[11], c2);
	pack_word(c[12], c[13], c[14], c[15], c3);

	s0 ^= m0;
	s1 ^= m1;
	s2 ^= m2;
	s3 ^= m3;

	c0 ^= m0;
	c1 ^= m1;
	c2 ^= m2;
	c3 ^= m3;

	unpack_word(s[0], s[1], s[2], s[3], s0);
	unpack_word(s[4], s[5], s[6], s[7], s1);
	unpack_word(s[8], s[9], s[10], s[11], s2);
	unpack_word(s[12], s[13], s[14], s[15], s3);

	unpack_word(c[0], c[1], c[2], c[3], c0);
	unpack_word(c[4], c[5], c[6], c[7], c1);
	unpack_word(c[8], c[9], c[10], c[11], c2);
	unpack_word(c[12], c[13], c[14], c[15], c3);

#endif

}

__device__ void rho_ud16G(
	const unsigned char* m,
	unsigned char* c,
	unsigned char* s,
	int len8) {

	unsigned char mp[16];

	padOG(m, mp, len8);

	g8AOG(s, c);
#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) ^= *(uint32_t*)(&mp[0]);
	*(uint32_t*)(&s[4]) ^= *(uint32_t*)(&mp[4]);
	*(uint32_t*)(&s[8]) ^= *(uint32_t*)(&mp[8]);
	*(uint32_t*)(&s[12]) ^= *(uint32_t*)(&mp[12]);

	for (int i = 0; i < 16; i++) {
		if (i < len8) {
			c[i] = c[i] ^ mp[i];
		}
		else {
			c[i] = 0;
		}
	}

#else

	rho_ud16_macro(0);
	rho_ud16_macro(1);
	rho_ud16_macro(2);
	rho_ud16_macro(3);
	rho_ud16_macro(4);
	rho_ud16_macro(5);
	rho_ud16_macro(6);
	rho_ud16_macro(7);
	rho_ud16_macro(8);
	rho_ud16_macro(9);
	rho_ud16_macro(10);
	rho_ud16_macro(11);
	rho_ud16_macro(12);
	rho_ud16_macro(13);
	rho_ud16_macro(14);
	rho_ud16_macro(15);

	for (int i = 0; i < 16; i++) {
		if (i < len8) {
			c[i] = c[i] ^ mp[i];
		}
		else {
			c[i] = 0;
		}
	}

#endif

}

__device__ void irho_eqov16G(
	unsigned char* m,
	const unsigned char* c,
	unsigned char* s) {

	g8AOG(s, m);

#ifdef ___ENABLE_WORD_CAST

	uint32_t c0 = *(uint32_t*)(&c[0]);
	uint32_t c1 = *(uint32_t*)(&c[4]);
	uint32_t c2 = *(uint32_t*)(&c[8]);
	uint32_t c3 = *(uint32_t*)(&c[12]);

	uint32_t s0 = *(uint32_t*)(&s[0]);
	uint32_t s1 = *(uint32_t*)(&s[4]);
	uint32_t s2 = *(uint32_t*)(&s[8]);
	uint32_t s3 = *(uint32_t*)(&s[12]);

	uint32_t m0 = *(uint32_t*)(&m[0]);
	uint32_t m1 = *(uint32_t*)(&m[4]);
	uint32_t m2 = *(uint32_t*)(&m[8]);
	uint32_t m3 = *(uint32_t*)(&m[12]);

	s0 ^= c0 ^ m0;
	s1 ^= c1 ^ m1;
	s2 ^= c2 ^ m2;
	s3 ^= c3 ^ m3;

	m0 ^= c0;
	m1 ^= c1;
	m2 ^= c2;
	m3 ^= c3;

	*(uint32_t*)(&s[0]) = s0;
	*(uint32_t*)(&s[4]) = s1;
	*(uint32_t*)(&s[8]) = s2;
	*(uint32_t*)(&s[12]) = s3;

	*(uint32_t*)(&m[0]) = m0;
	*(uint32_t*)(&m[4]) = m1;
	*(uint32_t*)(&m[8]) = m2;
	*(uint32_t*)(&m[12]) = m3;

#else

	uint32_t c0, c1, c2, c3;
	uint32_t s0, s1, s2, s3;
	uint32_t m0, m1, m2, m3;

	pack_word(m[0], m[1], m[2], m[3], m0);
	pack_word(m[4], m[5], m[6], m[7], m1);
	pack_word(m[8], m[9], m[10], m[11], m2);
	pack_word(m[12], m[13], m[14], m[15], m3);

	pack_word(s[0], s[1], s[2], s[3], s0);
	pack_word(s[4], s[5], s[6], s[7], s1);
	pack_word(s[8], s[9], s[10], s[11], s2);
	pack_word(s[12], s[13], s[14], s[15], s3);

	pack_word(c[0], c[1], c[2], c[3], c0);
	pack_word(c[4], c[5], c[6], c[7], c1);
	pack_word(c[8], c[9], c[10], c[11], c2);
	pack_word(c[12], c[13], c[14], c[15], c3);

	s0 ^= c0 ^ m0;
	s1 ^= c1 ^ m1;
	s2 ^= c2 ^ m2;
	s3 ^= c3 ^ m3;

	m0 ^= c0;
	m1 ^= c1;
	m2 ^= c2;
	m3 ^= c3;

	unpack_word(s[0], s[1], s[2], s[3], s0);
	unpack_word(s[4], s[5], s[6], s[7], s1);
	unpack_word(s[8], s[9], s[10], s[11], s2);
	unpack_word(s[12], s[13], s[14], s[15], s3);

	unpack_word(m[0], m[1], m[2], m[3], m0);
	unpack_word(m[4], m[5], m[6], m[7], m1);
	unpack_word(m[8], m[9], m[10], m[11], m2);
	unpack_word(m[12], m[13], m[14], m[15], m3);

#endif

}

__device__ void irho_ud16G(
	unsigned char* m,
	const unsigned char* c,
	unsigned char* s,
	int len8) {

	unsigned char cp[16];

	padOG(c, cp, len8);

	g8AOG(s, m);

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) ^= *(uint32_t*)(&cp[0]);
	*(uint32_t*)(&s[4]) ^= *(uint32_t*)(&cp[4]);
	*(uint32_t*)(&s[8]) ^= *(uint32_t*)(&cp[8]);
	*(uint32_t*)(&s[12]) ^= *(uint32_t*)(&cp[12]);

	for (int i = 0; i < len8; i++) {
		s[i] ^= m[i];
	}

	for (int i = 0; i < 16; i++) {
		if (i < len8) {
			m[i] = m[i] ^ cp[i];
		}
		else {
			m[i] = 0;
		}
	}

#else

	irho_ud16_macro(0);
	irho_ud16_macro(1);
	irho_ud16_macro(2);
	irho_ud16_macro(3);
	irho_ud16_macro(4);
	irho_ud16_macro(5);
	irho_ud16_macro(6);
	irho_ud16_macro(7);
	irho_ud16_macro(8);
	irho_ud16_macro(9);
	irho_ud16_macro(10);
	irho_ud16_macro(11);
	irho_ud16_macro(12);
	irho_ud16_macro(13);
	irho_ud16_macro(14);
	irho_ud16_macro(15);

	for (int i = 0; i < len8; i++) {
		s[i] ^= m[i];
	}

	for (int i = 0; i < 16; i++) {
		if (i < len8) {
			m[i] = m[i] ^ cp[i];
		}
		else {
			m[i] = 0;
		}
	}

#endif

}

__device__ void reset_lfsr_gf56OG(unsigned char* CNT) {

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&CNT[0]) = 0x00000001; // CNT3 CNT2 CNT1 CNT0
	*(uint32_t*)(&CNT[4]) = 0x00000000; // CNT7 CNT6 CNT5 CNT4

#else

	CNT[0] = 0x01;
	CNT[1] = 0x00;
	CNT[2] = 0x00;
	CNT[3] = 0x00;
	CNT[4] = 0x00;
	CNT[5] = 0x00;
	CNT[6] = 0x00;

#endif

}

__device__ void lfsr_gf56OG(unsigned char* CNT) {

#ifdef ___ENABLE_WORD_CAST

	uint32_t C0;
	uint32_t C1;
	uint32_t fb0;

	C0 = *(uint32_t*)(&CNT[0]); // CNT3 CNT2 CNT1 CNT0
	C1 = *(uint32_t*)(&CNT[4]); // CNT7 CNT6 CNT5 CNT4

	fb0 = 0;
	if (CNT[6] & 0x80) {
		fb0 = 0x95;
	}

	C1 = C1 << 1 | C0 >> 31;
	C0 = C0 << 1 ^ fb0;

	*(uint32_t*)(&CNT[0]) = C0;
	*(uint32_t*)(&CNT[4]) = C1;

#else

	uint32_t fb0 = CNT[6] >> 7;

	CNT[6] = (CNT[6] << 1) | (CNT[5] >> 7);
	CNT[5] = (CNT[5] << 1) | (CNT[4] >> 7);
	CNT[4] = (CNT[4] << 1) | (CNT[3] >> 7);
	CNT[3] = (CNT[3] << 1) | (CNT[2] >> 7);
	CNT[2] = (CNT[2] << 1) | (CNT[1] >> 7);
	CNT[1] = (CNT[1] << 1) | (CNT[0] >> 7);
	if (fb0 == 1) {
		CNT[0] = (CNT[0] << 1) ^ 0x95;
	}
	else {
		CNT[0] = (CNT[0] << 1);
	}

#endif

}

__device__ void block_cipherOG(
	unsigned char* s,
	const unsigned char* k, unsigned char* T,
	unsigned char* CNT, unsigned char D,
	skinny_ctrl* p_skinny_ctrl) {

	CNT[7] = D;
	p_skinny_ctrl->func_skinny_128_384_enc(s, p_skinny_ctrl, CNT, T, k);

}

__device__ void nonce_encryptionOG(
	const unsigned char* N,
	unsigned char* CNT,
	unsigned char* s, const unsigned char* k,
	unsigned char D,
	skinny_ctrl* p_skinny_ctrl) {

	block_cipherOG(s, k, (unsigned char*)N, CNT, D, p_skinny_ctrl);

}

__device__ void generate_tagOG(
	unsigned char** c, unsigned char* s,
	unsigned long long* clen) {

#ifdef ___ENABLE_WORD_CAST

	g8A_for_Tag_GenerationG(s, *c);

#else

	g8AOG(s, *c);

#endif
	* c = *c + 16;
	*c = *c - *clen;

}

__device__ unsigned long long msg_encryptionOG(
	const unsigned char** M, unsigned char** c,
	const unsigned char* N,
	unsigned char* CNT,
	unsigned char* s, const unsigned char* k,
	unsigned char D,
	unsigned long long mlen,
	skinny_ctrl* l_skinny_ctrl) {

	int len8;

	if (mlen >= 16) {
		len8 = 16;
		mlen = mlen - 16;
		rho_eqov16G(*M, *c, s);
	}
	else {
		len8 = mlen;
		mlen = 0;
		rho_ud16G(*M, *c, s, len8);
	}
	*c = *c + len8;
	*M = *M + len8;
	lfsr_gf56OG(CNT);
	if (mlen != 0) {
		nonce_encryptionOG(N, CNT, s, k, D, l_skinny_ctrl);
	}
	return mlen;

}

__device__ unsigned long long ad2msg_encryptionOG(
	const unsigned char** M,
	unsigned char* CNT,
	unsigned char* s, const unsigned char* k,
	unsigned char D,
	unsigned long long mlen,
	skinny_ctrl* l_skinny_ctrl) {

	unsigned char T[16];
	int len8;

	if (mlen <= 16) {
		len8 = mlen;
		mlen = 0;
	}
	else {
		len8 = 16;
		mlen = mlen - 16;
	}

	padOG(*M, T, len8);
	block_cipherOG(s, k, T, CNT, D, l_skinny_ctrl);
	lfsr_gf56OG(CNT);
	*M = *M + len8;

	return mlen;

}

__device__ unsigned long long ad_encryptionOG(
	const unsigned char** A, unsigned char* s,
	const unsigned char* k, unsigned long long adlen,
	unsigned char* CNT,
	unsigned char D,
	skinny_ctrl* l_skinny_ctrl) {

	unsigned char T[16];
	int len8;

	if (adlen >= 16) {
		len8 = 16;
		adlen = adlen - 16;

		rho_ad_eqov16G(*A, s);
	}
	else {
		len8 = adlen;
		adlen = 0;
		rho_ad_ud16G(*A, s, len8);
	}
	*A = *A + len8;
	lfsr_gf56OG(CNT);
	if (adlen != 0) {
		if (adlen >= 16) {
			len8 = 16;
			adlen = adlen - 16;
		}
		else {
			len8 = adlen;
			adlen = 0;
		}
		padOG(*A, T, len8);
		*A = *A + len8;
		block_cipherOG(s, k, T, CNT, D, l_skinny_ctrl);
		lfsr_gf56OG(CNT);
	}

	return adlen;

}


//////////////////////   Romulus N Op Ref   ////////////////////

__device__ unsigned long long msg_encryption_eqov16G(
	const unsigned char** M, unsigned char** c,
	const unsigned char* N,
	unsigned char* CNT,
	unsigned char* s, const unsigned char* k,
	unsigned char D,
	unsigned long long mlen,
	skinny_ctrl* p_skinny_ctrl) {

	rho_eqov16G(*M, *c, s);
	*c = *c + 16;
	*M = *M + 16;
	lfsr_gf56OG(CNT);
	nonce_encryptionOG(N, CNT, s, k, D, p_skinny_ctrl);
	return mlen - 16;

}

__device__ unsigned long long msg_encryption_ud16G(
	const unsigned char** M, unsigned char** c,
	const unsigned char* N,
	unsigned char* CNT,
	unsigned char* s, const unsigned char* k,
	unsigned char D,
	unsigned long long mlen,
	skinny_ctrl* p_skinny_ctrl) {

	rho_ud16G(*M, *c, s, mlen);
	*c = *c + mlen;
	*M = *M + mlen;
	lfsr_gf56OG(CNT);
	nonce_encryptionOG(N, CNT, s, k, D, p_skinny_ctrl);
	return 0;

}

__device__ unsigned long long ad_encryption_eqov32G(
	const unsigned char** A, unsigned char* s,
	const unsigned char* k, unsigned long long adlen,
	unsigned char* CNT,
	unsigned char D,
	skinny_ctrl* p_skinny_ctrl) {

	unsigned char T[16];

	rho_ad_eqov16G(*A, s);
	*A = *A + 16;
	lfsr_gf56OG(CNT);

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&T[0]) = *(uint32_t*)(&(*A)[0]);
	*(uint32_t*)(&T[4]) = *(uint32_t*)(&(*A)[4]);
	*(uint32_t*)(&T[8]) = *(uint32_t*)(&(*A)[8]);
	*(uint32_t*)(&T[12]) = *(uint32_t*)(&(*A)[12]);

#else

	T[0] = (*A)[0];
	T[1] = (*A)[1];
	T[2] = (*A)[2];
	T[3] = (*A)[3];
	T[4] = (*A)[4];
	T[5] = (*A)[5];
	T[6] = (*A)[6];
	T[7] = (*A)[7];
	T[8] = (*A)[8];
	T[9] = (*A)[9];
	T[10] = (*A)[10];
	T[11] = (*A)[11];
	T[12] = (*A)[12];
	T[13] = (*A)[13];
	T[14] = (*A)[14];
	T[15] = (*A)[15];

#endif

	* A = *A + 16;
	block_cipherOG(s, k, T, CNT, D, p_skinny_ctrl);
	lfsr_gf56OG(CNT);

	return adlen - 32;

}

__device__ unsigned long long ad_encryption_ov16G(
	const unsigned char** A, unsigned char* s,
	const unsigned char* k, unsigned long long adlen,
	unsigned char* CNT,
	unsigned char D,
	skinny_ctrl* p_skinny_ctrl) {

	unsigned char T[16];

	adlen = adlen - 16;
	rho_ad_eqov16G(*A, s);
	*A = *A + 16;
	lfsr_gf56OG(CNT);

	padOG(*A, T, adlen);
	*A = *A + adlen;
	block_cipherOG(s, k, T, CNT, D, p_skinny_ctrl);
	lfsr_gf56OG(CNT);

	return 0;

}

__device__ unsigned long long ad_encryption_eq16G(
	const unsigned char** A, unsigned char* s,
	unsigned char* CNT) {

	rho_ad_eqov16G(*A, s);
	*A = *A + 16;
	lfsr_gf56OG(CNT);

	return 0;

}

__device__ unsigned long long ad_encryption_ud16G(
	const unsigned char** A, unsigned char* s,
	unsigned long long adlen,
	unsigned char* CNT) {

	rho_ad_ud16G(*A, s, adlen);
	*A = *A + adlen;
	lfsr_gf56OG(CNT);

	return 0;

}






///////////////////////////////// romulus M Op & N Op /////////////////////////////

//implement constant memory
__device__ const unsigned char SBOXG_Op[]
= {
	// Original
	0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
	0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
	0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
	0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
	0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
	0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
	0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
	0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
	0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
	0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
	0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
	0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
	0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
	0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
	0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
	0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,
};

__device__ const unsigned char SBOXG2_Op[]
= {   // Original ^ c2(0x02)
	0x67, 0x4e, 0x68, 0x40, 0x49, 0x61, 0x41, 0x69, 0x57, 0x77, 0x58, 0x78, 0x51, 0x71, 0x59, 0x79,
	0x37, 0x8e, 0x38, 0x83, 0x8b, 0x31, 0x82, 0x39, 0x97, 0x27, 0x9a, 0x28, 0x92, 0x21, 0x9b, 0x29,
	0xe7, 0xce, 0xea, 0xc3, 0xcb, 0xe2, 0xc2, 0xeb, 0xd7, 0xf7, 0xda, 0xfa, 0xd2, 0xf2, 0xdb, 0xfb,
	0xa7, 0x1e, 0xaa, 0x10, 0x19, 0xa2, 0x11, 0xab, 0x07, 0xb7, 0x08, 0xba, 0x01, 0xb2, 0x09, 0xbb,
	0x30, 0x8a, 0x3e, 0x87, 0x8f, 0x36, 0x86, 0x3f, 0x93, 0x20, 0x9e, 0x2e, 0x96, 0x26, 0x9f, 0x2f,
	0x60, 0x48, 0x6e, 0x47, 0x4f, 0x66, 0x46, 0x6f, 0x50, 0x70, 0x5e, 0x7e, 0x56, 0x76, 0x5f, 0x7f,
	0xa3, 0x18, 0xae, 0x17, 0x1f, 0xa6, 0x16, 0xaf, 0x00, 0xb3, 0x0e, 0xbe, 0x06, 0xb6, 0x0f, 0xbf,
	0xe3, 0xca, 0xee, 0xc7, 0xcf, 0xe6, 0xc6, 0xef, 0xd3, 0xf3, 0xde, 0xfe, 0xd6, 0xf6, 0xdf, 0xff,
	0x34, 0x8c, 0x3a, 0x80, 0x89, 0x32, 0x81, 0x3b, 0x94, 0x24, 0x98, 0x2a, 0x91, 0x22, 0x99, 0x2b,
	0x64, 0x4c, 0x6a, 0x43, 0x4b, 0x62, 0x42, 0x6b, 0x54, 0x74, 0x5a, 0x7a, 0x52, 0x72, 0x5b, 0x7b,
	0xa4, 0x1c, 0xa8, 0x13, 0x1b, 0xa1, 0x12, 0xa9, 0x04, 0xb4, 0x0a, 0xb8, 0x02, 0xb1, 0x0b, 0xb9,
	0xe4, 0xcc, 0xe8, 0xc0, 0xc9, 0xe1, 0xc1, 0xe9, 0xd4, 0xf4, 0xd8, 0xf8, 0xd1, 0xf1, 0xd9, 0xf9,
	0x33, 0x88, 0x3c, 0x84, 0x8d, 0x35, 0x85, 0x3d, 0x90, 0x23, 0x9c, 0x2c, 0x95, 0x25, 0x9d, 0x2d,
	0x63, 0x4a, 0x6c, 0x44, 0x4d, 0x65, 0x45, 0x6d, 0x53, 0x73, 0x5c, 0x7c, 0x55, 0x75, 0x5d, 0x7d,
	0xa0, 0x1a, 0xac, 0x14, 0x1d, 0xa5, 0x15, 0xad, 0x03, 0xb0, 0x0c, 0xbc, 0x05, 0xb5, 0x0d, 0xbd,
	0xe0, 0xc8, 0xec, 0xc4, 0xcd, 0xe5, 0xc5, 0xed, 0xd0, 0xf0, 0xdc, 0xfc, 0xd5, 0xf5, 0xdd, 0xfd,
};


__device__ void EncryptG_Op(unsigned char* block, uint32_t* roundKeys)
{ //unsigned char* sboxG, unsigned char* sbox2G
	uint32_t* tk1;
	uint32_t* tk2;
	uint32_t t0;          // used in MACRO
	uint32_t t1;          // used in MACRO
	uint32_t t2;          // used in MACRO
	uint32_t t3;          // used in MACRO
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;

	// TK1

	  // load master key
	w0 = roundKeys[0];
	w1 = roundKeys[1];

	// 1st round
	// not need to store

	tk1 = &roundKeys[2];

	// 2nd, ... ,8th round
	for (int i = 0; i < 7; i++)
	{
		PERMUTATION_TK1();
	}

	// SB+AC+ShR+MC

#ifndef ___ENABLE_WORD_CAST
	pack_word(block[0], block[1], block[2], block[3], w0);
	pack_word(block[4], block[5], block[6], block[7], w1);
	pack_word(block[8], block[9], block[10], block[11], w2);
	pack_word(block[12], block[13], block[14], block[15], w3);
#else
	w0 = *(uint32_t*)(&block[0]);
	w1 = *(uint32_t*)(&block[4]);
	w2 = *(uint32_t*)(&block[8]);
	w3 = *(uint32_t*)(&block[12]);
#endif

	tk2 = &roundKeys[16];

	// 1st, ... ,32th or 48th round
#ifndef ___NUM_OF_ROUNDS_56
	for (int j = 0; j < 2; j++)
#else
	for (int j = 0; j < 3; j++)
#endif
	{
		tk1 = &roundKeys[0];
		for (int i = 0; i < 8; i++)
		{
			SKINNY_MAING_OP();
		}
		
	}

	// 33th , ... ,40th or 49th, .... ,56th round
	{
		tk1 = &roundKeys[0];
		for (int i = 0; i < 4; i++)
		{
			SKINNY_MAING_OP();
		}
	}
#ifndef ___ENABLE_WORD_CAST
	unpack_word(block[0], block[1], block[2], block[3], w0);
	unpack_word(block[4], block[5], block[6], block[7], w1);
	unpack_word(block[8], block[9], block[10], block[11], w2);
	unpack_word(block[12], block[13], block[14], block[15], w3);
#else
	* (uint32_t*)(&block[0]) = w0;
	*(uint32_t*)(&block[4]) = w1;
	*(uint32_t*)(&block[8]) = w2;
	*(uint32_t*)(&block[12]) = w3;
#endif

}

//skinny

__device__ void skinny_128_384_enc12_12G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	(void)K;

	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pack_word(T[0], T[1], T[2], T[3], pt[4]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pack_word(T[8], T[9], T[10], T[11], pt[6]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pt[4] = *(uint32_t*)(&T[0]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pt[6] = *(uint32_t*)(&T[8]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);
#endif

	RunEncryptionKeyScheduleTK2G(pskinny_ctrl->roundKeys);
	EncryptG_Op(input, pskinny_ctrl->roundKeys);

}

__device__ void skinny_128_384_enc123_12G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pack_word(T[0], T[1], T[2], T[3], pt[4]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pack_word(T[8], T[9], T[10], T[11], pt[6]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);

	pack_word(K[0], K[1], K[2], K[3], pt[8]);
	pack_word(K[7], K[4], K[5], K[6], pt[9]);
	pack_word(K[8], K[9], K[10], K[11], pt[10]);
	pack_word(K[15], K[12], K[13], K[14], pt[11]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);

	pt[4] = *(uint32_t*)(&T[0]);
	pack_word(T[7], T[4], T[5], T[6], pt[5]);
	pt[6] = *(uint32_t*)(&T[8]);
	pack_word(T[15], T[12], T[13], T[14], pt[7]);

	pt[8] = *(uint32_t*)(&K[0]);
	pack_word(K[7], K[4], K[5], K[6], pt[9]);
	pt[10] = *(uint32_t*)(&K[8]);
	pack_word(K[15], K[12], K[13], K[14], pt[11]);
#endif

#ifdef ___SKINNY_LOOP
	RunEncryptionKeyScheduleTK3G(pskinny_ctrl->roundKeys, RCOG);
#else
	RunEncryptionKeyScheduleTK3G_Op(pskinny_ctrl->roundKeys);
#endif
	RunEncryptionKeyScheduleTK2G(pskinny_ctrl->roundKeys);
	EncryptG_Op(input, pskinny_ctrl->roundKeys);

	pskinny_ctrl->func_skinny_128_384_enc = skinny_128_384_enc12_12G_Op;

}

__device__ extern void skinny_128_384_enc1_1G_Op(unsigned char* input, skinny_ctrl* pskinny_ctrl, unsigned char* CNT, unsigned char* T, const unsigned char* K)
{
	(void)T;
	(void)K;

	uint32_t* pt = &pskinny_ctrl->roundKeys[0];
#ifndef ___ENABLE_WORD_CAST
	pack_word(CNT[0], CNT[1], CNT[2], CNT[3], pt[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#else
	pt[0] = *(uint32_t*)(&CNT[0]);
	pack_word(CNT[7], CNT[4], CNT[5], CNT[6], pt[1]);
#endif

	EncryptG_Op(input, pskinny_ctrl->roundKeys);

}