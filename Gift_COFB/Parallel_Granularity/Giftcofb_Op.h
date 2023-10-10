#include "params.h"

/*****************************************************************************
* The round constants according to the fixsliced representation.
*****************************************************************************/
const u32 rconst[40] = {
	0x10000008, 0x80018000, 0x54000002, 0x01010181,
	0x8000001f, 0x10888880, 0x6001e000, 0x51500002,
	0x03030180, 0x8000002f, 0x10088880, 0x60016000,
	0x41500002, 0x03030080, 0x80000027, 0x10008880,
	0x4001e000, 0x11500002, 0x03020180, 0x8000002b,
	0x10080880, 0x60014000, 0x01400002, 0x02020080,
	0x80000021, 0x10000080, 0x0001c000, 0x51000002,
	0x03010180, 0x8000002e, 0x10088800, 0x60012000,
	0x40500002, 0x01030080, 0x80000006, 0x10008808,
	0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

/*****************************************************************************
* The first 20 rkeys are computed using the classical representation before
* being rearranged into fixsliced representations depending on round numbers.
* The 60 remaining rkeys are directly computed in fixscliced representations.
*****************************************************************************/
static void precompute_rkeys(u32* rkey, const u8* key) {
	u32 tmp;
	//classical initialization
	rkey[0] = U32BIG(((u32*)key)[3]);
	rkey[1] = U32BIG(((u32*)key)[1]);
	rkey[2] = U32BIG(((u32*)key)[2]);
	rkey[3] = U32BIG(((u32*)key)[0]);
	// classical keyschedule
	for (int i = 0; i < 16; i += 2) {
		rkey[i + 4] = rkey[i + 1];
		rkey[i + 5] = KEY_UPDATE(rkey[i]);
	}
	// transposition to fixsliced representations
	for (int i = 0; i < 20; i += 10) {

		REARRANGE_RKEY_0(rkey[i]);
		REARRANGE_RKEY_0(rkey[i + 1]);
		REARRANGE_RKEY_1(rkey[i + 2]);
		REARRANGE_RKEY_1(rkey[i + 3]);
		REARRANGE_RKEY_2(rkey[i + 4]);
		REARRANGE_RKEY_2(rkey[i + 5]);
		REARRANGE_RKEY_3(rkey[i + 6]);
		REARRANGE_RKEY_3(rkey[i + 7]);
	}
	// keyschedule according to fixsliced representations
	for (int i = 20; i < 80; i += 10) {
		rkey[i] = rkey[i - 19];
		rkey[i + 1] = KEY_TRIPLE_UPDATE_0(rkey[i - 20]);
		rkey[i + 2] = KEY_DOUBLE_UPDATE_1(rkey[i - 17]);
		rkey[i + 3] = KEY_TRIPLE_UPDATE_1(rkey[i - 18]);
		rkey[i + 4] = KEY_DOUBLE_UPDATE_2(rkey[i - 15]);
		rkey[i + 5] = KEY_TRIPLE_UPDATE_2(rkey[i - 16]);
		rkey[i + 6] = KEY_DOUBLE_UPDATE_3(rkey[i - 13]);
		rkey[i + 7] = KEY_TRIPLE_UPDATE_3(rkey[i - 14]);
		rkey[i + 8] = KEY_DOUBLE_UPDATE_4(rkey[i - 11]);
		rkey[i + 9] = KEY_TRIPLE_UPDATE_4(rkey[i - 12]);
		SWAPMOVE(rkey[i], rkey[i], 0x00003333, 16);
		SWAPMOVE(rkey[i], rkey[i], 0x55554444, 1);
		SWAPMOVE(rkey[i + 1], rkey[i + 1], 0x55551100, 1);
	}
}

/*****************************************************************************
* Encryption of a single 128-bit block with GIFTb-128 (used in GIFT-COFB).
*****************************************************************************/
static void giftb128(u8* ctext, const u8* ptext, const u32* rkey) {
	u32 tmp, state[4];
	state[0] = U32BIG(((u32*)ptext)[0]);
	state[1] = U32BIG(((u32*)ptext)[1]);
	state[2] = U32BIG(((u32*)ptext)[2]);
	state[3] = U32BIG(((u32*)ptext)[3]);

	QUINTUPLE_ROUND(state, rkey, rconst + 0);
	QUINTUPLE_ROUND(state, rkey + 10, rconst + 5);
	QUINTUPLE_ROUND(state, rkey + 20, rconst + 10);
	QUINTUPLE_ROUND(state, rkey + 30, rconst + 15);
	QUINTUPLE_ROUND(state, rkey + 40, rconst + 20);
	QUINTUPLE_ROUND(state, rkey + 50, rconst + 25);
	QUINTUPLE_ROUND(state, rkey + 60, rconst + 30);
	QUINTUPLE_ROUND(state, rkey + 70, rconst + 35);
	U8BIG(ctext, state[0]);
	U8BIG(ctext + 4, state[1]);
	U8BIG(ctext + 8, state[2]);
	U8BIG(ctext + 12, state[3]);
}

static void paddingC(u32* d, const u32* s, const u32 no_of_bytes) {
	u32 i;
	if (no_of_bytes == 0) {
		d[0] = 0x00000080; // little-endian
		d[1] = 0x00000000;
		d[2] = 0x00000000;
		d[3] = 0x00000000;
	}
	else if (no_of_bytes < BLOCKBYTES) {
		for (i = 0; i < no_of_bytes / 4 + 1; i++)
			d[i] = s[i];
		d[i - 1] &= ~(0xffffffffL << (no_of_bytes % 4) * 8);
		d[i - 1] |= 0x00000080L << (no_of_bytes % 4) * 8;
		for (; i < 4; i++)
			d[i] = 0x00000000;
	}
	else {
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
}

static void RHO1(u32* d, u32* y, u32* m, u32 n) {
	u32 tmp0, tmp1;
	G(y);
	paddingC(d, m, n);
	XOR_BLOCK(d, d, y);
}

static void RHO(u32* y, u32* m, u32* x, u32* c, u32 n) {
	XOR_BLOCK(c, y, m);
	RHO1(x, y, m, n);
}

static void RHO_PRIME(u32* y, u32* c, u32* x, u32* m, u32 n) {
	XOR_BLOCK(m, y, c);
	RHO1(x, y, m, n);
}
/////////// GPU implementation

__device__ __constant__ u32 rconstG_Op[40] = {
	0x10000008, 0x80018000, 0x54000002, 0x01010181,
	0x8000001f, 0x10888880, 0x6001e000, 0x51500002,
	0x03030180, 0x8000002f, 0x10088880, 0x60016000,
	0x41500002, 0x03030080, 0x80000027, 0x10008880,
	0x4001e000, 0x11500002, 0x03020180, 0x8000002b,
	0x10080880, 0x60014000, 0x01400002, 0x02020080,
	0x80000021, 0x10000080, 0x0001c000, 0x51000002,
	0x03010180, 0x8000002e, 0x10088800, 0x60012000,
	0x40500002, 0x01030080, 0x80000006, 0x10008808,
	0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};


/*****************************************************************************
* Encryption of a single 128-bit block with GIFTb-128 (used in GIFT-COFB).
*****************************************************************************/
__device__ void giftb128G_Op(u8* ctext, const u8* ptext, const u32* rkey) {
	u32 tmp, state[4];
	state[0] = U32BIG(((u32*)ptext)[0]);
	state[1] = U32BIG(((u32*)ptext)[1]);
	state[2] = U32BIG(((u32*)ptext)[2]);
	state[3] = U32BIG(((u32*)ptext)[3]);

	QUINTUPLE_ROUND(state, rkey, rconstG_Op + 0);
	QUINTUPLE_ROUND(state, rkey + 10, rconstG_Op + 5);
	QUINTUPLE_ROUND(state, rkey + 20, rconstG_Op + 10);
	QUINTUPLE_ROUND(state, rkey + 30, rconstG_Op + 15);
	QUINTUPLE_ROUND(state, rkey + 40, rconstG_Op + 20);
	QUINTUPLE_ROUND(state, rkey + 50, rconstG_Op + 25);
	QUINTUPLE_ROUND(state, rkey + 60, rconstG_Op + 30);
	QUINTUPLE_ROUND(state, rkey + 70, rconstG_Op + 35);
	U8BIG(ctext, state[0]);
	U8BIG(ctext + 4, state[1]);
	U8BIG(ctext + 8, state[2]);
	U8BIG(ctext + 12, state[3]);
}

__device__ void paddingG_Op(u32* d, const u32* s, const u32 no_of_bytes) {
	u32 i;
	if (no_of_bytes == 0) {
		d[0] = 0x00000080; // little-endian
		d[1] = 0x00000000;
		d[2] = 0x00000000;
		d[3] = 0x00000000;
	}
	else if (no_of_bytes < BLOCKBYTES) {
		for (i = 0; i < no_of_bytes / 4 + 1; i++)
			d[i] = s[i];
		d[i - 1] &= ~(0xffffffffL << (no_of_bytes % 4) * 8);
		d[i - 1] |= 0x00000080L << (no_of_bytes % 4) * 8;
		for (; i < 4; i++)
			d[i] = 0x00000000;
	}
	else {
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
}

__device__ void RHO1G_Op(u32* d, u32* y, u32* m, u32 n) {
	u32 tmp0, tmp1;
	G(y);
	paddingG_Op(d, m, n);
	XOR_BLOCK(d, d, y);
}

__device__ void RHOG_Op(u32* y, u32* m, u32* x, u32* c, u32 n) {
	XOR_BLOCK(c, y, m);
	RHO1G_Op(x, y, m, n);
}

__device__ void RHO_PRIMEG_Op(u32* y, u32* c, u32* x, u32* m, u32 n) {
	XOR_BLOCK(m, y, c);
	RHO1G_Op(x, y, m, n);
}

__device__ void precompute_rkeysG_OpBased(u32* rkey, const u8* key) {
	u32 tmp;

	//classical initialization
	rkey[0] = U32BIG(((u32*)key)[3]);
	rkey[1] = U32BIG(((u32*)key)[1]);
	rkey[2] = U32BIG(((u32*)key)[2]);
	rkey[3] = U32BIG(((u32*)key)[0]);
#pragma unroll	
	for (int i = 0; i < 16; i += 2) {
		rkey[i + 4] = rkey[i + 1];
		rkey[i + 5] = KEY_UPDATE(rkey[i]);
	}

#pragma unroll	
	// transposition to fixsliced representations
	for (int i = 0; i < 20; i += 10) {

		REARRANGE_RKEY_0(rkey[i]);
		REARRANGE_RKEY_0(rkey[i + 1]);
		REARRANGE_RKEY_1(rkey[i + 2]);
		REARRANGE_RKEY_1(rkey[i + 3]);
		REARRANGE_RKEY_2(rkey[i + 4]);
		REARRANGE_RKEY_2(rkey[i + 5]);
		REARRANGE_RKEY_3(rkey[i + 6]);
		REARRANGE_RKEY_3(rkey[i + 7]);
	}
#pragma unroll	
	// keyschedule according to fixsliced representations
	for (int i = 20; i < 80; i += 10) {
		rkey[i] = rkey[i - 19];
		rkey[i + 1] = KEY_TRIPLE_UPDATE_0(rkey[i - 20]);
		rkey[i + 2] = KEY_DOUBLE_UPDATE_1(rkey[i - 17]);
		rkey[i + 3] = KEY_TRIPLE_UPDATE_1(rkey[i - 18]);
		rkey[i + 4] = KEY_DOUBLE_UPDATE_2(rkey[i - 15]);
		rkey[i + 5] = KEY_TRIPLE_UPDATE_2(rkey[i - 16]);
		rkey[i + 6] = KEY_DOUBLE_UPDATE_3(rkey[i - 13]);
		rkey[i + 7] = KEY_TRIPLE_UPDATE_3(rkey[i - 14]);
		rkey[i + 8] = KEY_DOUBLE_UPDATE_4(rkey[i - 11]);
		rkey[i + 9] = KEY_TRIPLE_UPDATE_4(rkey[i - 12]);
		SWAPMOVE(rkey[i], rkey[i], 0x00003333, 16);
		SWAPMOVE(rkey[i], rkey[i], 0x55554444, 1);
		SWAPMOVE(rkey[i + 1], rkey[i + 1], 0x55551100, 1);
	}

}


/*****************************************************************************
* Optimised Version - register
*****************************************************************************/

__device__ void giftb128G_NewOp(u8* ctext, const u8* ptext, u32* rkey) {
	u32 tmp, s0, s1, s2, s3;
	s0 = U32BIG(((u32*)ptext)[0]);
	s1 = U32BIG(((u32*)ptext)[1]);
	s2 = U32BIG(((u32*)ptext)[2]);
	s3 = U32BIG(((u32*)ptext)[3]);

	QUINTUPLE_ROUND_Op(rkey, rconstG_Op + 0);
	QUINTUPLE_ROUND_Op(rkey + 10, rconstG_Op + 5);
	QUINTUPLE_ROUND_Op(rkey + 20, rconstG_Op + 10);
	QUINTUPLE_ROUND_Op(rkey + 30, rconstG_Op + 15);
	QUINTUPLE_ROUND_Op(rkey + 40, rconstG_Op + 20);
	QUINTUPLE_ROUND_Op(rkey + 50, rconstG_Op + 25);
	QUINTUPLE_ROUND_Op(rkey + 60, rconstG_Op + 30);
	QUINTUPLE_ROUND_Op(rkey + 70, rconstG_Op + 35);
	U8BIG(ctext, s0);
	U8BIG(ctext + 4, s1);
	U8BIG(ctext + 8, s2);
	U8BIG(ctext + 12, s3);
}


/*****************************************************************************
* Optimised Version - Share Mem
*****************************************************************************/

__device__ __shared__ uint32_t TableG[80];

__device__ void precompute_rkeysG_SharedOp(const u8* key) {
	u32 tmp;

	TableG[0] = U32BIG(((u32*)key)[3]);
	TableG[1] = U32BIG(((u32*)key)[1]);
	TableG[2] = U32BIG(((u32*)key)[2]);
	TableG[3] = U32BIG(((u32*)key)[0]);

	for (int i = 0; i < 16; i += 2) {
		TableG[i + 4] = TableG[i + 1];
		TableG[i + 5] = KEY_UPDATE(TableG[i]);
	}
#pragma unroll
	// transposition to fixsliced representations
	for (int i = 0; i < 20; i += 10) {
		REARRANGE_RKEY_0(TableG[i]);
		REARRANGE_RKEY_0(TableG[i + 1]);
		REARRANGE_RKEY_1(TableG[i + 2]);
		REARRANGE_RKEY_1(TableG[i + 3]);
		REARRANGE_RKEY_2(TableG[i + 4]);
		REARRANGE_RKEY_2(TableG[i + 5]);
		REARRANGE_RKEY_3(TableG[i + 6]);
		REARRANGE_RKEY_3(TableG[i + 7]);
	}
#pragma unroll
	// keyschedule according to fixsliced representations
	for (int i = 20; i < 80; i += 10) {

		TableG[i] = TableG[i - 19];
		TableG[i + 1] = KEY_TRIPLE_UPDATE_0(TableG[i - 20]);
		TableG[i + 2] = KEY_DOUBLE_UPDATE_1(TableG[i - 17]);
		TableG[i + 3] = KEY_TRIPLE_UPDATE_1(TableG[i - 18]);
		TableG[i + 4] = KEY_DOUBLE_UPDATE_2(TableG[i - 15]);
		TableG[i + 5] = KEY_TRIPLE_UPDATE_2(TableG[i - 16]);
		TableG[i + 6] = KEY_DOUBLE_UPDATE_3(TableG[i - 13]);
		TableG[i + 7] = KEY_TRIPLE_UPDATE_3(TableG[i - 14]);
		TableG[i + 8] = KEY_DOUBLE_UPDATE_4(TableG[i - 11]);
		TableG[i + 9] = KEY_TRIPLE_UPDATE_4(TableG[i - 12]);
		SWAPMOVE(TableG[i], TableG[i], 0x00003333, 16);
		SWAPMOVE(TableG[i], TableG[i], 0x55554444, 1);
		SWAPMOVE(TableG[i + 1], TableG[i + 1], 0x55551100, 1);
	}
}

__device__ void giftb128G_SharedOp(u8* ctext, const u8* ptext) {
	u32 tmp, state[4];

	state[0] = U32BIG(((u32*)ptext)[0]);
	state[1] = U32BIG(((u32*)ptext)[1]);
	state[2] = U32BIG(((u32*)ptext)[2]);
	state[3] = U32BIG(((u32*)ptext)[3]);

	QUINTUPLE_ROUND(state, TableG, rconstG_Op + 0);
	QUINTUPLE_ROUND(state, TableG + 10, rconstG_Op + 5);
	QUINTUPLE_ROUND(state, TableG + 20, rconstG_Op + 10);
	QUINTUPLE_ROUND(state, TableG + 30, rconstG_Op + 15);
	QUINTUPLE_ROUND(state, TableG + 40, rconstG_Op + 20);
	QUINTUPLE_ROUND(state, TableG + 50, rconstG_Op + 25);
	QUINTUPLE_ROUND(state, TableG + 60, rconstG_Op + 30);
	QUINTUPLE_ROUND(state, TableG + 70, rconstG_Op + 35);
	U8BIG(ctext, state[0]);
	U8BIG(ctext + 4, state[1]);
	U8BIG(ctext + 8, state[2]);
	U8BIG(ctext + 12, state[3]);
}


/*****************************************************************************
* Optimised Version - Fine Thread
*****************************************************************************/
__device__ __shared__ uint32_t TableFG[10240];

__device__ void precompute_rkeysG_FineOp(const u8* key) {
	u32 tmp;

	TableFG[0 + ((threadIdx.x / fineLevel) * 80)] = U32BIG(((u32*)key)[3]);
	TableFG[1 + ((threadIdx.x / fineLevel) * 80)] = U32BIG(((u32*)key)[1]);
	TableFG[2 + ((threadIdx.x / fineLevel) * 80)] = U32BIG(((u32*)key)[2]);
	TableFG[3 + ((threadIdx.x / fineLevel) * 80)] = U32BIG(((u32*)key)[0]);

	for (int i = 0; i < 16; i += 2) { //int i = 0; i < 16; i += 2

		TableFG[i + 4 + ((threadIdx.x / fineLevel) * 80)] = TableFG[i + 1 + ((threadIdx.x / fineLevel) * 80)];
		TableFG[i + 5 + ((threadIdx.x / fineLevel) * 80)] = KEY_UPDATE(TableFG[i + ((threadIdx.x / fineLevel) * 80)]);
	}

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)20 / (double)fineLevel)));
	int e = (c + ceil(((double)20 / (double)fineLevel)));

#pragma unroll
	for (int i = c; i < e; i += 10) {
		REARRANGE_RKEY_0(TableFG[i + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_0(TableFG[i + 1 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_1(TableFG[i + 2 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_1(TableFG[i + 3 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_2(TableFG[i + 4 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_2(TableFG[i + 5 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_3(TableFG[i + 6 + ((threadIdx.x / fineLevel) * 80)]);
		REARRANGE_RKEY_3(TableFG[i + 7 + ((threadIdx.x / fineLevel) * 80)]);
	}
	__syncthreads();


	c = (innertid * fineLevel * ceil((((double)80 - (double)20) / (double)fineLevel)));
	e = (c + ceil(((double)60 / (double)fineLevel)));
#pragma unroll
	// keyschedule according to fixsliced representations
	for (int i = c; i < e; i += 10) { //20 to 80

		TableFG[i + ((threadIdx.x / fineLevel) * 80)] = TableFG[i - 19 + ((threadIdx.x / fineLevel) * 80)];
		TableFG[i + 1 + ((threadIdx.x / fineLevel) * 80)] = KEY_TRIPLE_UPDATE_0(TableFG[i - 20 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 2 + ((threadIdx.x / fineLevel) * 80)] = KEY_DOUBLE_UPDATE_1(TableFG[i - 17 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 3 + ((threadIdx.x / fineLevel) * 80)] = KEY_TRIPLE_UPDATE_1(TableFG[i - 18 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 4 + ((threadIdx.x / fineLevel) * 80)] = KEY_DOUBLE_UPDATE_2(TableFG[i - 15 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 5 + ((threadIdx.x / fineLevel) * 80)] = KEY_TRIPLE_UPDATE_2(TableFG[i - 16 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 6 + ((threadIdx.x / fineLevel) * 80)] = KEY_DOUBLE_UPDATE_3(TableFG[i - 13 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 7 + ((threadIdx.x / fineLevel) * 80)] = KEY_TRIPLE_UPDATE_3(TableFG[i - 14 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 8 + ((threadIdx.x / fineLevel) * 80)] = KEY_DOUBLE_UPDATE_4(TableFG[i - 11 + ((threadIdx.x / fineLevel) * 80)]);
		TableFG[i + 9 + ((threadIdx.x / fineLevel) * 80)] = KEY_TRIPLE_UPDATE_4(TableFG[i - 12 + ((threadIdx.x / fineLevel) * 80)]);
		SWAPMOVE(TableFG[i + ((threadIdx.x / fineLevel) * 80)], TableFG[i + ((threadIdx.x / fineLevel) * 80)], 0x00003333, 16);
		SWAPMOVE(TableFG[i + ((threadIdx.x / fineLevel) * 80)], TableFG[i + ((threadIdx.x / fineLevel) * 80)], 0x55554444, 1);
		SWAPMOVE(TableFG[i + 1 + ((threadIdx.x / fineLevel) * 80)], TableFG[i + 1 + ((threadIdx.x / fineLevel) * 80)], 0x55551100, 1);

	}

	__syncthreads();

}

__device__ void giftb128G_FineOp_Register(u8* ctext, const u8* ptext) {

	u32 tmp, s0, s1, s2, s3;
	s0 = U32BIG(((u32*)ptext)[0]);
	s1 = U32BIG(((u32*)ptext)[1]);
	s2 = U32BIG(((u32*)ptext)[2]);
	s3 = U32BIG(((u32*)ptext)[3]);

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)20 / (double)fineLevel)));
	int e = (c + ceil(((double)20 / (double)fineLevel)));

	QUINTUPLE_ROUND_Op(TableFG + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 0);
	QUINTUPLE_ROUND_Op(TableFG + 10 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 5);
	QUINTUPLE_ROUND_Op(TableFG + 20 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 10);
	QUINTUPLE_ROUND_Op(TableFG + 30 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 15);
	QUINTUPLE_ROUND_Op(TableFG + 40 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 20);
	QUINTUPLE_ROUND_Op(TableFG + 50 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 25);
	QUINTUPLE_ROUND_Op(TableFG + 60 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 30);
	QUINTUPLE_ROUND_Op(TableFG + 70 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 35);

	U8BIG(ctext, s0);
	U8BIG(ctext + 4, s1);
	U8BIG(ctext + 8, s2);
	U8BIG(ctext + 12, s3);
}


__device__ void giftb128G_FineOp(u8* ctext, const u8* ptext) {
	u32 tmp, state[4];

	state[0] = U32BIG(((u32*)ptext)[0]);
	state[1] = U32BIG(((u32*)ptext)[1]);
	state[2] = U32BIG(((u32*)ptext)[2]);
	state[3] = U32BIG(((u32*)ptext)[3]);

	QUINTUPLE_ROUND(state, TableFG + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 0);
	QUINTUPLE_ROUND(state, TableFG + 10 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 5);
	QUINTUPLE_ROUND(state, TableFG + 20 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 10);
	QUINTUPLE_ROUND(state, TableFG + 30 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 15);
	QUINTUPLE_ROUND(state, TableFG + 40 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 20);
	QUINTUPLE_ROUND(state, TableFG + 50 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 25);
	QUINTUPLE_ROUND(state, TableFG + 60 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 30);
	QUINTUPLE_ROUND(state, TableFG + 70 + ((threadIdx.x / fineLevel) * 80), rconstG_Op + 35);

	U8BIG(ctext, state[0]);
	U8BIG(ctext + 4, state[1]);
	U8BIG(ctext + 8, state[2]);
	U8BIG(ctext + 12, state[3]);
}