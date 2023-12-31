#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;


// 4 words key and IV, 12 init rounds, 1024 rounds before reinit = 1040
#define BUF_SIZE 1040

typedef struct {
	u32 lfsr[BUF_SIZE];
	u32 nfsr[BUF_SIZE];
	u32* lptr;
	u32* nptr;
	u32 count;
	u64 acc;
	u64 reg;
} grain_ctx;

static const uint32_t mvo0 = 0x22222222;
static const uint32_t mvo1 = 0x18181818;
static const uint32_t mvo2 = 0x07800780;
static const uint32_t mvo3 = 0x007f8000;
static const uint32_t mvo4 = 0x80000000;

static const uint32_t mve0 = 0x44444444;
static const uint32_t mve1 = 0x30303030;
static const uint32_t mve2 = 0x0f000f00;
static const uint32_t mve3 = 0x00ff0000;

void grain_reinit(grain_ctx* grain)
{
	*(u32*)(grain->lfsr) = *(u32*)(grain->lptr);
	*(u32*)(grain->lfsr + 1) = *(u32*)(grain->lptr + 1);
	*(u32*)(grain->lfsr + 2) = *(u32*)(grain->lptr + 2);
	*(u32*)(grain->lfsr + 3) = *(u32*)(grain->lptr + 3);

	*(u32*)(grain->nfsr + 0) = *(u32*)(grain->nptr + 0);
	*(u32*)(grain->nfsr + 1) = *(u32*)(grain->nptr + 1);
	*(u32*)(grain->nfsr + 2) = *(u32*)(grain->nptr + 2);
	*(u32*)(grain->nfsr + 3) = *(u32*)(grain->nptr + 3);

	grain->lptr = grain->lfsr;
	grain->nptr = grain->nfsr;
	grain->count = 4;
}


u32 next_keystream(grain_ctx* grain)
{
	u64 ln0 = (((u64) * (grain->lptr + 1)) << 32) | *(grain->lptr),
		ln1 = (((u64) * (grain->lptr + 2)) << 32) | *(grain->lptr + 1),
		ln2 = (((u64) * (grain->lptr + 3)) << 32) | *(grain->lptr + 2),
		ln3 = (((u64) * (grain->lptr + 3)));
	u64 nn0 = (((u64) * (grain->nptr + 1)) << 32) | *(grain->nptr),
		nn1 = (((u64) * (grain->nptr + 2)) << 32) | *(grain->nptr + 1),
		nn2 = (((u64) * (grain->nptr + 3)) << 32) | *(grain->nptr + 2),
		nn3 = (((u64) * (grain->nptr + 3)));

	// f
	grain->lfsr[grain->count] = (ln0 ^ ln3) ^ ((ln1 ^ ln2) >> 6) ^ (ln0 >> 7) ^ (ln2 >> 17);

	// g                        s0    b0        b26       b96       b56             b91 + b27b59
	grain->nfsr[grain->count] = ln0 ^ nn0 ^ (nn0 >> 26) ^ nn3 ^ (nn1 >> 24) ^ (((nn0 & nn1) ^ nn2) >> 27) ^
		//     b3b67                   b11b13                        b17b18
		((nn0 & nn2) >> 3) ^ ((nn0 >> 11) & (nn0 >> 13)) ^ ((nn0 >> 17) & (nn0 >> 18)) ^
		//       b40b48                        b61b65                      b68b84
		((nn1 >> 8) & (nn1 >> 16)) ^ ((nn1 >> 29) & (nn2 >> 1)) ^ ((nn2 >> 4) & (nn2 >> 20)) ^
		//                   b88b92b93b95
		((nn2 >> 24) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31)) ^
		//              b22b24b25                                  b70b78b82
		((nn0 >> 22) & (nn0 >> 24) & (nn0 >> 25)) ^ ((nn2 >> 6) & (nn2 >> 14) & (nn2 >> 18));

	grain->count++;
	grain->lptr++;
	grain->nptr++;

	// move the state to the beginning of the buffers
	if (grain->count >= BUF_SIZE) grain_reinit(grain);

	return (nn0 >> 2) ^ (nn0 >> 15) ^ (nn1 >> 4) ^ (nn1 >> 13) ^ nn2 ^ (nn2 >> 9) ^ (nn2 >> 25) ^ (ln2 >> 29) ^
		((nn0 >> 12) & (ln0 >> 8)) ^ ((ln0 >> 13) & (ln0 >> 20)) ^ ((nn2 >> 31) & (ln1 >> 10)) ^
		((ln1 >> 28) & (ln2 >> 15)) ^ ((nn0 >> 12) & (nn2 >> 31) & (ln2 >> 30));
}

void auth_accumulate(grain_ctx* grain, u16 ms, u16 msg)
{
	/* updates the authentication module using the
	 * MAC stream (ms) and the plaintext (msg)
	 */
	u16 mstmp = ms;
	u16 acctmp = 0;
	u32 regtmp = (u32)ms << 16;

	for (int i = 0; i < 16; i++) {
		u64 mask = 0x00;
		u32 mask_rem = 0x00;
		if (msg & 0x0001) {
			mask = ~mask; // all ones
			mask_rem = 0x0000ffff;
		}

		grain->acc ^= grain->reg & mask;
		grain->reg >>= 1;

		acctmp ^= regtmp & mask_rem;
		regtmp >>= 1;

		mstmp >>= 1;

		msg >>= 1;
	}

	grain->reg |= ((u64)ms << 48);
	grain->acc ^= ((u64)acctmp << 48);

}

void auth_accumulate8(grain_ctx* grain, u8 ms, u8 msg)
{
	/* updates the authentication module using the
	 * MAC stream (ms) and the plaintext (msg)
	 */
	u8 mstmp = ms;
	u8 acctmp = 0;
	u16 regtmp = (u16)ms << 8;

	for (int i = 0; i < 8; i++) {
		u64 mask = 0x00;
		u32 mask_rem = 0x00;
		if (msg & 0x01) {
			mask = ~mask; // all ones
			mask_rem = 0x00ff;
		}

		grain->acc ^= grain->reg & mask;
		grain->reg >>= 1;

		acctmp ^= regtmp & mask_rem;
		regtmp >>= 1;

		mstmp >>= 1;

		msg >>= 1;
	}

	grain->reg |= ((u64)ms << 56);
	grain->acc ^= ((u64)acctmp << 56);

}

void grain_init(grain_ctx* grain, const u8* key, const u8* iv)
{
	// load key, and IV along with padding
	memcpy(grain->nfsr, key, 16);
	memcpy(grain->lfsr, iv, 12);
	*(u32*)(grain->lfsr + 3) = (u32)0x7fffffff; // 0xfffffffe in little endian, LSB first

	grain->count = 4;
	grain->nptr = grain->nfsr;
	grain->lptr = grain->lfsr;

	register u32 ks;
	for (int i = 0; i < 8; i++) {
		ks = next_keystream(grain);
		grain->nfsr[i + 4] ^= ks;
		grain->lfsr[i + 4] ^= ks;
	}

	// add the key in the feedback, "FP(1)" and initialize auth module
	grain->acc = 0;
	for (int i = 0; i < 2; i++) {
		// initialize accumulator
		ks = next_keystream(grain);
		grain->acc |= ((u64)ks << (32 * i));
		grain->lfsr[i + 12] ^= *(u32*)(key + 4 * i);
	}

	grain->reg = 0;
	for (int i = 0; i < 2; i++) {
		// initialize register
		ks = next_keystream(grain);
		grain->reg |= ((u64)ks << (32 * i));
		grain->lfsr[i + 14] ^= *(u32*)(key + 8 + 4 * i);
	}
}


u16 getmb(u32 num)
{
	// compress x using the mask 0xAAAAAAAA to extract the (odd) MAC bits, LSB first
	register u32 t;
	register u32 x = num & 0xAAAAAAAA;
	t = x & mvo0; x = (x ^ t) | (t >> 1);
	t = x & mvo1; x = (x ^ t) | (t >> 2);
	t = x & mvo2; x = (x ^ t) | (t >> 4);
	t = x & mvo3; x = (x ^ t) | (t >> 8);
	t = x & mvo4; x = (x ^ t) | (t >> 16);

	return (u16)x;
}

u16 getkb(u32 num)
{
	// compress x using the mask 0x55555555 to extract the (even) key bits, LSB first
	register u32 t;
	register u32 x = num & 0x55555555;
	t = x & mve0; x = (x ^ t) | (t >> 1);
	t = x & mve1; x = (x ^ t) | (t >> 2);
	t = x & mve2; x = (x ^ t) | (t >> 4);
	t = x & mve3; x = (x ^ t) | (t >> 8);

	return (u16)x;
}

int encode_derOp(unsigned long long len, u8** der)
{
	unsigned long long len_tmp;
	int der_len = 0;

	if (len < 128) {
		*der = (u8*)malloc(1);
		(*der)[0] = len;
		return 1;
	}

	len_tmp = len;
	do {
		len_tmp >>= 8;
		der_len++;
	} while (len_tmp != 0);

	// one extra byte to describe the number of bytes used
	*der = (u8*)malloc(der_len + 1);
	(*der)[0] = 0x80 | der_len;

	len_tmp = len;
	for (int i = der_len; i > 0; i--) {
		(*der)[i] = len_tmp & 0xff;	// mod 256
		len_tmp >>= 8;
	}

	return der_len + 1;
}