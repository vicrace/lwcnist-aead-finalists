#include <stdio.h>
#include <string.h>
#include "params.h"

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned long u32;
typedef long long i64;

const u8 ISAP_IV1[] = { 0x01,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };
const u8 ISAP_IV2[] = { 0x02,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };
const u8 ISAP_IV3[] = { 0x03,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(7-(n)))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(7-(n))))

#define U64BIG(x) \
    ((ROTR(x, 8) & (0xFF000000FF000000ULL)) | \
     (ROTR(x,24) & (0x00FF000000FF0000ULL)) | \
     (ROTR(x,40) & (0x0000FF000000FF00ULL)) | \
     (ROTR(x,56) & (0x000000FF000000FFULL)))

#define ROUND(C,Const) \
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, Const[1][0]);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, Const[2][0]);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, Const[2][1] - Const[2][0]);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, Const[3][0]);\
    x0 ^= x4;\
    x4 = ROTR(x4, Const[4][0]);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, Const[1][1] - Const[1][0]);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, Const[3][1] - Const[3][0]);\
    t4 ^= x4;\
    x4 = ROTR(x4, Const[4][1] - Const[4][0]);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, Const[0][0]);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, Const[0][1] - Const[0][0]);\
    x0 ^= t0;


#define P12(Const)    \
    ROUND(0xf0,Const);\
    ROUND(0xe1,Const);\
    ROUND(0xd2,Const);\
    ROUND(0xc3,Const);\
    ROUND(0xb4,Const);\
    ROUND(0xa5,Const);\
    ROUND(0x96,Const);\
    ROUND(0x87,Const);\
    ROUND(0x78,Const);\
    ROUND(0x69,Const);\
    ROUND(0x5a,Const);\
    ROUND(0x4b,Const);


#define P6(Const) ({\
    ROUND(0x96,Const);\
    ROUND(0x87,Const);\
    ROUND(0x78,Const);\
    ROUND(0x69,Const);\
    ROUND(0x5a,Const);\
    ROUND(0x4b,Const);\
})


#define P1(Const) ({\
    ROUND(0x4b, Const);\
})

static const int R[5][2] = {
	{19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}
};


void isap_rk(
	const u8* k,
	const u8* iv,
	const u8* y,
	const u64 ylen,
	u8* out,
	const u64 outlen
) {
	const u64* k64 = (u64*)k;
	const u64* iv64 = (u64*)iv;
	u64* out64 = (u64*)out;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;

	// Init state
	t0 = t1 = t2 = t3 = t4 = 0;
	x0 = U64BIG(k64[0]);
	x1 = U64BIG(k64[1]);
	x2 = U64BIG(iv64[0]);
	x3 = x4 = 0;
	P12(R);

	// Absorb Y
	for (size_t i = 0; i < ylen * 8 - 1; i++) {
		size_t cur_byte_pos = i / 8;
		size_t cur_bit_pos = 7 - (i % 8);
		u8 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0 ^= ((u64)cur_bit) << 56;
		P12(R);
	}
	u8 cur_bit = ((y[ylen - 1]) & 0x01) << 7;
	x0 ^= ((u64)cur_bit) << 56;
	P12(R);

	// Extract K*
	out64[0] = U64BIG(x0);
	out64[1] = U64BIG(x1);
	if (outlen == 24) {
		out64[2] = U64BIG(x2);
	}
}


void isap_mac(
	const u8* k,
	const u8* npub,
	const u8* ad, const u64 adlen,
	const u8* c, const u64 clen,
	u8* tag
) {
	u8 state[ISAP_STATE_SZ];
	const u64* npub64 = (u64*)npub;
	u64* state64 = (u64*)state;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;
	t0 = t1 = t2 = t3 = t4 = 0;

	// Init state
	x0 = U64BIG(npub64[0]);
	x1 = U64BIG(npub64[1]);
	x2 = U64BIG(((u64*)ISAP_IV1)[0]);
	x3 = x4 = 0;
	P12(R);

	// Absorb AD
	u32 rem_bytes = adlen;
	u64* src64 = (u64*)ad;
	u32 idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12(R);
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12(R);
			x0 ^= 0x8000000000000000ULL;
			P12(R);
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = ad[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12(R);
			break;
		}
	}

	// Domain seperation
	x4 ^= 0x0000000000000001ULL;

	// Absorb C
	rem_bytes = clen;
	src64 = (u64*)c;
	idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12(R);
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12(R);
			x0 ^= 0x8000000000000000ULL;
			P12(R);
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = c[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12(R);
			break;
		}
	}

	// Derive K*
	state64[0] = U64BIG(x0);
	state64[1] = U64BIG(x1);
	state64[2] = U64BIG(x2);
	state64[3] = U64BIG(x3);
	state64[4] = U64BIG(x4);
	isap_rk(k, ISAP_IV2, (u8*)state64, CRYPTO_KEYBYTES, (u8*)state64, CRYPTO_KEYBYTES);
	x0 = U64BIG(state64[0]);
	x1 = U64BIG(state64[1]);
	x2 = U64BIG(state64[2]);
	x3 = U64BIG(state64[3]);
	x4 = U64BIG(state64[4]);

	// Squeeze tag
	P12(R);
	unsigned long long* tag64 = (u64*)tag;
	tag64[0] = U64BIG(x0);
	tag64[1] = U64BIG(x1);
}


////////// Op32 ////////////
typedef struct
{
	u32 e;
	u32 o;
} u32_2;

// Round constants, bit-interleaved
u32 rc_o[12] = { 0xc, 0xc, 0x9, 0x9, 0xc, 0xc, 0x9, 0x9, 0x6, 0x6, 0x3, 0x3 };
u32 rc_e[12] = { 0xc, 0x9, 0xc, 0x9, 0x6, 0x3, 0x6, 0x3, 0xc, 0x9, 0xc, 0x9 };

u64 U64BIG32(u64 x)
{
	return ((((x) & 0x00000000000000FFULL) << 56) | (((x) & 0x000000000000FF00ULL) << 40) |
		(((x) & 0x0000000000FF0000ULL) << 24) | (((x) & 0x00000000FF000000ULL) << 8) |
		(((x) & 0x000000FF00000000ULL) >> 8) | (((x) & 0x0000FF0000000000ULL) >> 24) |
		(((x) & 0x00FF000000000000ULL) >> 40) | (((x) & 0xFF00000000000000ULL) >> 56));
}

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
void to_bit_interleaving(u32_2 * out, u64 in)
{
	u32 hi = (in) >> 32;
	u32 lo = (u32)(in);
	u32 r0, r1;
	r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
	r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
	r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
	r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
	r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
	r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
	r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
	r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
	(*out).e = (lo & 0x0000FFFF) | (hi << 16);
	(*out).o = (lo >> 16) | (hi & 0xFFFF0000);
}

void from_bit_interleaving(u64 * out, u32_2 in)
{
	u32 lo = ((in).e & 0x0000FFFF) | ((in).o << 16);
	u32 hi = ((in).e >> 16) | ((in).o & 0xFFFF0000);
	u32 r0, r1;
	r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
	r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
	r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
	r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
	r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
	r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
	r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
	r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
	*out = (u64)hi << 32 | lo;
}

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

void static inline PX(u32 rounds, u32_2 * x0, u32_2 * x1, u32_2 * x2, u32_2 * x3, u32_2 * x4) {
	u32_2 t0, t1, t2, t3, t4;
	for (u32 r = 12 - rounds; r < 12; r++) {
		/* rcon */
		(*x2).e ^= rc_e[r];
		(*x2).o ^= rc_o[r];
		/* non-linear layer */
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		(*x4).e ^= (*x3).e;
		(*x4).o ^= (*x3).o;
		(*x2).e ^= (*x1).e;
		(*x2).o ^= (*x1).o;
		(t0).e = (*x0).e;
		(t0).o = (*x0).o;
		(t4).e = (*x4).e;
		(t4).o = (*x4).o;
		(t3).e = (*x3).e;
		(t3).o = (*x3).o;
		(t1).e = (*x1).e;
		(t1).o = (*x1).o;
		(t2).e = (*x2).e;
		(t2).o = (*x2).o;
		(*x0).e = t0.e ^ (~t1.e & t2.e);
		(*x0).o = t0.o ^ (~t1.o & t2.o);
		(*x2).e = t2.e ^ (~t3.e & t4.e);
		(*x2).o = t2.o ^ (~t3.o & t4.o);
		(*x4).e = t4.e ^ (~t0.e & t1.e);
		(*x4).o = t4.o ^ (~t0.o & t1.o);
		(*x1).e = t1.e ^ (~t2.e & t3.e);
		(*x1).o = t1.o ^ (~t2.o & t3.o);
		(*x3).e = t3.e ^ (~t4.e & t0.e);
		(*x3).o = t3.o ^ (~t4.o & t0.o);
		(*x1).e ^= (*x0).e;
		(*x1).o ^= (*x0).o;
		(*x3).e ^= (*x2).e;
		(*x3).o ^= (*x2).o;
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		/* linear layer */
		t0.e = (*x0).e ^ ROTR32((*x0).o, 4);
		t0.o = (*x0).o ^ ROTR32((*x0).e, 5);
		t1.e = (*x1).e ^ ROTR32((*x1).e, 11);
		t1.o = (*x1).o ^ ROTR32((*x1).o, 11);
		t2.e = (*x2).e ^ ROTR32((*x2).o, 2);
		t2.o = (*x2).o ^ ROTR32((*x2).e, 3);
		t3.e = (*x3).e ^ ROTR32((*x3).o, 3);
		t3.o = (*x3).o ^ ROTR32((*x3).e, 4);
		t4.e = (*x4).e ^ ROTR32((*x4).e, 17);
		t4.o = (*x4).o ^ ROTR32((*x4).o, 17);
		(*x0).e ^= ROTR32(t0.o, 9);
		(*x0).o ^= ROTR32(t0.e, 10);
		(*x1).e ^= ROTR32(t1.o, 19);
		(*x1).o ^= ROTR32(t1.e, 20);
		(*x2).e ^= t2.o;
		(*x2).o ^= ROTR32(t2.e, 1);
		(*x3).e ^= ROTR32(t3.e, 5);
		(*x3).o ^= ROTR32(t3.o, 5);
		(*x4).e ^= ROTR32(t4.o, 3);
		(*x4).o ^= ROTR32(t4.e, 4);
		(*x2).e = ~(*x2).e;
		(*x2).o = ~(*x2).o;
	}
}

#define P_sB PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sE PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sH PX(12,&x0,&x1,&x2,&x3,&x4)
#define P_sK PX(12,&x0,&x1,&x2,&x3,&x4)

void isap_rk_O32(
	const u8 * k,
	const u8 * iv,
	const u8 * y,
	u8 * out,
	const u8 outlen)
{
	// State variables
	u32_2 x0, x1, x2, x3, x4;

	// Initialize
	to_bit_interleaving(&x0, U64BIG32(*(u64*)(k + 0)));
	to_bit_interleaving(&x1, U64BIG32(*(u64*)(k + 8)));
	to_bit_interleaving(&x2, U64BIG32(*(u64*)(iv + 0)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sK;

	// Absorb Y, bit by bit
	for (u8 i = 0; i < 127; i++) {
		u8 cur_byte_pos = i / 8;
		u8 cur_bit_pos = 7 - (i % 8);
		u32 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0.o ^= ((u32)cur_bit) << 24;
		P_sB;
	}
	u8 cur_bit = ((y[15]) & 0x01) << 7;
	x0.o ^= ((u32)cur_bit) << (24);

	// Squeeze - Derive K*
	P_sK;
	*(u32*)(out + 0) = x0.o;
	*(u32*)(out + 4) = x0.e;
	*(u32*)(out + 8) = x1.o;
	*(u32*)(out + 12) = x1.e;
	if (outlen > 16) {
		*(u32*)(out + 16) = x2.o;
		*(u32*)(out + 20) = x2.e;
	}
}

void isap_mac_O32(
	const u8 * k,
	const u8 * npub,
	const u8 * ad, u64 adlen,
	const u8 * c, u64 clen,
	u8 * tag)
{
	// State and temporary variables
	u32_2 x0, x1, x2, x3, x4;
	u32_2 t0;
	u64 tmp0;

	// Initialize
	to_bit_interleaving(&x0, U64BIG32(*(u64*)npub + 0));
	to_bit_interleaving(&x1, U64BIG32(*(u64*)(npub + 8)));
	to_bit_interleaving(&x2, U64BIG32(*(u64*)(ISAP_IV1)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sH;

	// Absorb full lanes of AD
	while (adlen >= 8)
	{
		to_bit_interleaving(&t0, U64BIG32(*(u64*)ad));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		adlen -= ISAP_rH / 8;
		ad += ISAP_rH / 8;
		P_sH;
	}

	// Absorb partial lane of AD and add padding
	if (adlen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;
		for (i = 0; i < adlen; i++)
		{
			tmp0_bytes[i] = *ad;
			ad += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleaving(&t0, U64BIG32(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sH;
	}

	// Absorb AD padding if not already done before
	if (adlen == 0)
	{
		x0.o ^= 0x80000000;
		P_sH;
	}

	// Domain Seperation
	x4.e ^= ((u32)0x01);

	// Absorb full lanes of C
	while (clen >= 8)
	{
		to_bit_interleaving(&t0, U64BIG32(*(u64*)c));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sH;
		clen -= ISAP_rH / 8;
		c += ISAP_rH / 8;
	}

	// Absorb partial lane of C and add padding
	if (clen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;
		for (i = 0; i < clen; i++)
		{
			tmp0_bytes[i] = *c;
			c += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleaving(&t0, U64BIG32(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sH;
	}

	// Absorb C padding if not already done before
	if (clen == 0)
	{
		x0.o ^= 0x80000000;
		P_sH;
	}

	// Finalize - Derive Ka*
	u64 y64[CRYPTO_KEYBYTES / 8];
	from_bit_interleaving(&tmp0, x0);
	y64[0] = U64BIG32(tmp0);
	from_bit_interleaving(&tmp0, x1);
	y64[1] = U64BIG32(tmp0);
	u32 ka_star32[CRYPTO_KEYBYTES / 4];
	isap_rk_O32(k, ISAP_IV1, (u8*)y64, (u8*)ka_star32, CRYPTO_KEYBYTES);

	// Finalize - Squeeze T
	x0.o = ka_star32[0];
	x0.e = ka_star32[1];
	x1.o = ka_star32[2];
	x1.e = ka_star32[3];
	P_sH;
	from_bit_interleaving(&tmp0, x0);
	*(u64*)(tag + 0) = U64BIG32(tmp0);
	from_bit_interleaving(&tmp0, x1);
	*(u64*)(tag + 8) = U64BIG32(tmp0);
}

//////////////////////// GPU implementation
__device__ const u8 ISAP_IV1G[] = { 0x01,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };
__device__ const u8 ISAP_IV2G[] = { 0x02,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };
__device__ const u8 ISAP_IV3G[] = { 0x03,128,ISAP_rH,1,ISAP_sH,ISAP_sB,ISAP_sE,ISAP_sK };
__device__  const int RG[5][2] = {
	{19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}
};

#define ROUNDG(C) \
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, 39);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, 1);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, 5);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, 10);\
    x0 ^= x4;\
    x4 = ROTR(x4, 7);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, 22);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, 7);\
    t4 ^= x4;\
    x4 = ROTR(x4, 34);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, 19);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, 9);\
    x0 ^= t0;

//9 = 28-19
//34 = 41-7
//7 = 17-10
//22 = 61-39
//5 = 5

#define P12G \
    ROUNDG(0xf0);\
    ROUNDG(0xe1);\
    ROUNDG(0xd2);\
    ROUNDG(0xc3);\
    ROUNDG(0xb4);\
    ROUNDG(0xa5);\
    ROUNDG(0x96);\
    ROUNDG(0x87);\
    ROUNDG(0x78);\
    ROUNDG(0x69);\
    ROUNDG(0x5a);\
    ROUNDG(0x4b);\

__device__ void isap_rkG(
	const u8* k,
	const u8* iv,
	const u8* y,
	const u64 ylen,
	u8* out,
	const u64 outlen
) {
	const u64* k64 = (u64*)k;
	const u64* iv64 = (u64*)iv;
	u64* out64 = (u64*)out;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;

	// Init state
	t0 = t1 = t2 = t3 = t4 = 0;
	x0 = U64BIG(k64[0]);
	x1 = U64BIG(k64[1]);
	x2 = U64BIG(iv64[0]);
	x3 = x4 = 0;
	P12(RG);

	// Absorb Y
	for (size_t i = 0; i < ylen * 8 - 1; i++) {
		size_t cur_byte_pos = i / 8;
		size_t cur_bit_pos = 7 - (i % 8);
		u8 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0 ^= ((u64)cur_bit) << 56;
		P12(RG);
	}
	u8 cur_bit = ((y[ylen - 1]) & 0x01) << 7;
	x0 ^= ((u64)cur_bit) << 56;
	P12(RG);

	// Extract K*
	out64[0] = U64BIG(x0);
	out64[1] = U64BIG(x1);
	if (outlen == 24) {
		out64[2] = U64BIG(x2);
	}
}

__device__ void isap_macG(
	const u8* k,
	const u8* npub,
	const u8* ad, const u64 adlen,
	const u8* c, const u64 clen,
	u8* tag
) {
	u8 state[ISAP_STATE_SZ];
	const u64* npub64 = (u64*)npub;
	u64* state64 = (u64*)state;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;
	t0 = t1 = t2 = t3 = t4 = 0;

	// Init state
	x0 = U64BIG(npub64[0]);
	x1 = U64BIG(npub64[1]);
	x2 = U64BIG(((u64*)ISAP_IV1G)[0]);
	x3 = x4 = 0;
	P12(RG);

	// Absorb AD
	u32 rem_bytes = adlen;
	u64* src64 = (u64*)ad;
	u32 idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12(RG);
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12(RG);
			x0 ^= 0x8000000000000000ULL;
			P12(RG);
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = ad[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12(RG);
			break;
		}
	}

	// Domain seperation
	x4 ^= 0x0000000000000001ULL;

	// Absorb C
	rem_bytes = clen;
	src64 = (u64*)c;
	idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12(RG);
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12(RG);
			x0 ^= 0x8000000000000000ULL;
			P12(RG);
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = c[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12(RG);
			break;
		}
	}

	// Derive K*
	state64[0] = U64BIG(x0);
	state64[1] = U64BIG(x1);
	state64[2] = U64BIG(x2);
	state64[3] = U64BIG(x3);
	state64[4] = U64BIG(x4);
	isap_rkG(k, ISAP_IV2G, (u8*)state64, CRYPTO_KEYBYTES, (u8*)state64, CRYPTO_KEYBYTES);
	x0 = U64BIG(state64[0]);
	x1 = U64BIG(state64[1]);
	x2 = U64BIG(state64[2]);
	x3 = U64BIG(state64[3]);
	x4 = U64BIG(state64[4]);

	// Squeeze tag
	P12(RG);
	unsigned long long* tag64 = (u64*)tag;
	tag64[0] = U64BIG(x0);
	tag64[1] = U64BIG(x1);
}


__device__ void isap_rkGT(
	const u8* k,
	const u8* iv,
	const u8* y,
	const u64 ylen,
	u8* out,
	const u64 outlen
) {
	const u64* k64 = (u64*)k;
	const u64* iv64 = (u64*)iv;
	u64* out64 = (u64*)out;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;

	// Init state
	t0 = t1 = t2 = t3 = t4 = 0;
	x0 = U64BIG(k64[0]);
	x1 = U64BIG(k64[1]);
	x2 = U64BIG(iv64[0]);
	x3 = x4 = 0;
	P12G;

#pragma unroll
	// Absorb Y
	for (size_t i = 0; i < ylen * 8 - 1; i++) {
		size_t cur_byte_pos = i / 8;
		size_t cur_bit_pos = 7 - (i % 8);
		u8 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0 ^= ((u64)cur_bit) << 56;
		P12G;
	}
	u8 cur_bit = ((y[ylen - 1]) & 0x01) << 7;
	x0 ^= ((u64)cur_bit) << 56;
	P12G;

	// Extract K*
	out64[0] = U64BIG(x0);
	out64[1] = U64BIG(x1);
	if (outlen == 24) {
		out64[2] = U64BIG(x2);
	}
}

__device__ void isap_macGT(
	const u8* k,
	const u8* npub,
	const u8* ad, const u64 adlen,
	const u8* c, const u64 clen,
	u8* tag
) {
	u8 state[ISAP_STATE_SZ];
	const u64* npub64 = (u64*)npub;
	u64* state64 = (u64*)state;
	u64 x0, x1, x2, x3, x4;
	u64 t0, t1, t2, t3, t4;
	t0 = t1 = t2 = t3 = t4 = 0;

	// Init state
	x0 = U64BIG(npub64[0]);
	x1 = U64BIG(npub64[1]);
	x2 = U64BIG(((u64*)ISAP_IV1G)[0]);
	x3 = x4 = 0;
	P12G;

	// Absorb AD
	u32 rem_bytes = adlen;
	u64* src64 = (u64*)ad;
	u32 idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12G;
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12G;
			x0 ^= 0x8000000000000000ULL;
			P12G;
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = ad[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12G;
			break;
		}
	}

	// Domain seperation
	x4 ^= 0x0000000000000001ULL;

	// Absorb C
	rem_bytes = clen;
	src64 = (u64*)c;
	idx64 = 0;
	while (1) {
		if (rem_bytes > ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			idx64++;
			P12G;
			rem_bytes -= ISAP_rH_SZ;
		}
		else if (rem_bytes == ISAP_rH_SZ) {
			x0 ^= U64BIG(src64[idx64]);
			P12G;
			x0 ^= 0x8000000000000000ULL;
			P12G;
			break;
		}
		else {
			u64 lane64;
			u8* lane8 = (u8*)&lane64;
			u32 idx8 = idx64 * 8;
			for (u32 i = 0; i < 8; i++) {
				if (i < (rem_bytes)) {
					lane8[i] = c[idx8];
					idx8++;
				}
				else if (i == rem_bytes) {
					lane8[i] = 0x80;
				}
				else {
					lane8[i] = 0x00;
				}
			}
			x0 ^= U64BIG(lane64);
			P12G;
			break;
		}
	}

	// Derive K*
	state64[0] = U64BIG(x0);
	state64[1] = U64BIG(x1);
	state64[2] = U64BIG(x2);
	state64[3] = U64BIG(x3);
	state64[4] = U64BIG(x4);
	isap_rkGT(k, ISAP_IV2G, (u8*)state64, CRYPTO_KEYBYTES, (u8*)state64, CRYPTO_KEYBYTES);
	x0 = U64BIG(state64[0]);
	x1 = U64BIG(state64[1]);
	x2 = U64BIG(state64[2]);
	x3 = U64BIG(state64[3]);
	x4 = U64BIG(state64[4]);

	// Squeeze tag
	P12G;
	unsigned long long* tag64 = (u64*)tag;
	tag64[0] = U64BIG(x0);
	tag64[1] = U64BIG(x1);
}


////////// Op32 GPU ////////////

// Round constants, bit-interleaved
__device__ u32 rc_oG[12] = { 0xc, 0xc, 0x9, 0x9, 0xc, 0xc, 0x9, 0x9, 0x6, 0x6, 0x3, 0x3 };
__device__ u32 rc_eG[12] = { 0xc, 0x9, 0xc, 0x9, 0x6, 0x3, 0x6, 0x3, 0xc, 0x9, 0xc, 0x9 };

__device__ u64 U64BIG32G(u64 x)
{
	return ((((x) & 0x00000000000000FFULL) << 56) | (((x) & 0x000000000000FF00ULL) << 40) |
		(((x) & 0x0000000000FF0000ULL) << 24) | (((x) & 0x00000000FF000000ULL) << 8) |
		(((x) & 0x000000FF00000000ULL) >> 8) | (((x) & 0x0000FF0000000000ULL) >> 24) |
		(((x) & 0x00FF000000000000ULL) >> 40) | (((x) & 0xFF00000000000000ULL) >> 56));
}

// Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
__device__ void to_bit_interleavingG(u32_2 * out, u64 in)
{
	u32 hi = (in) >> 32;
	u32 lo = (u32)(in);
	u32 r0, r1;
	r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
	r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
	r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
	r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
	r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
	r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
	r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
	r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
	(*out).e = (lo & 0x0000FFFF) | (hi << 16);
	(*out).o = (lo >> 16) | (hi & 0xFFFF0000);
}

__device__ void from_bit_interleavingG(u64 * out, u32_2 in)
{
	u32 lo = ((in).e & 0x0000FFFF) | ((in).o << 16);
	u32 hi = ((in).e >> 16) | ((in).o & 0xFFFF0000);
	u32 r0, r1;
	r0 = (lo ^ (lo >> 8)) & 0x0000FF00, lo ^= r0 ^ (r0 << 8);
	r0 = (lo ^ (lo >> 4)) & 0x00F000F0, lo ^= r0 ^ (r0 << 4);
	r0 = (lo ^ (lo >> 2)) & 0x0C0C0C0C, lo ^= r0 ^ (r0 << 2);
	r0 = (lo ^ (lo >> 1)) & 0x22222222, lo ^= r0 ^ (r0 << 1);
	r1 = (hi ^ (hi >> 8)) & 0x0000FF00, hi ^= r1 ^ (r1 << 8);
	r1 = (hi ^ (hi >> 4)) & 0x00F000F0, hi ^= r1 ^ (r1 << 4);
	r1 = (hi ^ (hi >> 2)) & 0x0C0C0C0C, hi ^= r1 ^ (r1 << 2);
	r1 = (hi ^ (hi >> 1)) & 0x22222222, hi ^= r1 ^ (r1 << 1);
	*out = (u64)hi << 32 | lo;
}


__device__ void static inline PXG(u32 rounds, u32_2 * x0, u32_2 * x1, u32_2 * x2, u32_2 * x3, u32_2 * x4) {
	u32_2 t0, t1, t2, t3, t4;

	for (u32 r = 12 - rounds; r < 12; r++) {
		/* rcon */
		(*x2).e ^= rc_eG[r];
		(*x2).o ^= rc_oG[r];
		/* non-linear layer */
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		(*x4).e ^= (*x3).e;
		(*x4).o ^= (*x3).o;
		(*x2).e ^= (*x1).e;
		(*x2).o ^= (*x1).o;
		(t0).e = (*x0).e;
		(t0).o = (*x0).o;
		(t4).e = (*x4).e;
		(t4).o = (*x4).o;
		(t3).e = (*x3).e;
		(t3).o = (*x3).o;
		(t1).e = (*x1).e;
		(t1).o = (*x1).o;
		(t2).e = (*x2).e;
		(t2).o = (*x2).o;
		(*x0).e = t0.e ^ (~t1.e & t2.e);
		(*x0).o = t0.o ^ (~t1.o & t2.o);
		(*x2).e = t2.e ^ (~t3.e & t4.e);
		(*x2).o = t2.o ^ (~t3.o & t4.o);
		(*x4).e = t4.e ^ (~t0.e & t1.e);
		(*x4).o = t4.o ^ (~t0.o & t1.o);
		(*x1).e = t1.e ^ (~t2.e & t3.e);
		(*x1).o = t1.o ^ (~t2.o & t3.o);
		(*x3).e = t3.e ^ (~t4.e & t0.e);
		(*x3).o = t3.o ^ (~t4.o & t0.o);
		(*x1).e ^= (*x0).e;
		(*x1).o ^= (*x0).o;
		(*x3).e ^= (*x2).e;
		(*x3).o ^= (*x2).o;
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		/* linear layer */
		t0.e = (*x0).e ^ ROTR32((*x0).o, 4);
		t0.o = (*x0).o ^ ROTR32((*x0).e, 5);
		t1.e = (*x1).e ^ ROTR32((*x1).e, 11);
		t1.o = (*x1).o ^ ROTR32((*x1).o, 11);
		t2.e = (*x2).e ^ ROTR32((*x2).o, 2);
		t2.o = (*x2).o ^ ROTR32((*x2).e, 3);
		t3.e = (*x3).e ^ ROTR32((*x3).o, 3);
		t3.o = (*x3).o ^ ROTR32((*x3).e, 4);
		t4.e = (*x4).e ^ ROTR32((*x4).e, 17);
		t4.o = (*x4).o ^ ROTR32((*x4).o, 17);
		(*x0).e ^= ROTR32(t0.o, 9);
		(*x0).o ^= ROTR32(t0.e, 10);
		(*x1).e ^= ROTR32(t1.o, 19);
		(*x1).o ^= ROTR32(t1.e, 20);
		(*x2).e ^= t2.o;
		(*x2).o ^= ROTR32(t2.e, 1);
		(*x3).e ^= ROTR32(t3.e, 5);
		(*x3).o ^= ROTR32(t3.o, 5);
		(*x4).e ^= ROTR32(t4.o, 3);
		(*x4).o ^= ROTR32(t4.e, 4);
		(*x2).e = ~(*x2).e;
		(*x2).o = ~(*x2).o;
	}
}

#define P_sBG PXG(12,&x0,&x1,&x2,&x3,&x4)
#define P_sEG PXG(12,&x0,&x1,&x2,&x3,&x4)
#define P_sHG PXG(12,&x0,&x1,&x2,&x3,&x4)
#define P_sKG PXG(12,&x0,&x1,&x2,&x3,&x4)

__device__ void isap_rk_O32G(
	const u8 * k,
	const u8 * iv,
	const u8 * y,
	u8 * out,
	const u8 outlen)
{
	// State variables
	u32_2 x0, x1, x2, x3, x4;

	// Initialize
	to_bit_interleavingG(&x0, U64BIG32G(*(u64*)(k + 0)));
	to_bit_interleavingG(&x1, U64BIG32G(*(u64*)(k + 8)));
	to_bit_interleavingG(&x2, U64BIG32G(*(u64*)(iv + 0)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sKG;

	// Absorb Y, bit by bit
	for (u8 i = 0; i < 127; i++) {
		u8 cur_byte_pos = i / 8;
		u8 cur_bit_pos = 7 - (i % 8);
		u32 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0.o ^= ((u32)cur_bit) << 24;
		P_sBG;
	}
	u8 cur_bit = ((y[15]) & 0x01) << 7;
	x0.o ^= ((u32)cur_bit) << (24);

	// Squeeze - Derive K*
	P_sKG;
	*(u32*)(out + 0) = x0.o;
	*(u32*)(out + 4) = x0.e;
	*(u32*)(out + 8) = x1.o;
	*(u32*)(out + 12) = x1.e;
	if (outlen > 16) {
		*(u32*)(out + 16) = x2.o;
		*(u32*)(out + 20) = x2.e;
	}
}

__device__ void isap_mac_O32G(
	const u8 * k,
	const u8 * npub,
	const u8 * ad, u64 adlen,
	const u8 * c, u64 clen,
	u8 * tag)
{
	// State and temporary variables
	u32_2 x0, x1, x2, x3, x4;
	u32_2 t0;
	u64 tmp0;

	// Initialize
	to_bit_interleavingG(&x0, U64BIG32G(*(u64*)npub + 0));
	to_bit_interleavingG(&x1, U64BIG32G(*(u64*)(npub + 8)));
	to_bit_interleavingG(&x2, U64BIG32G(*(u64*)(ISAP_IV1G)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sHG;

	// Absorb full lanes of AD
	while (adlen >= 8)
	{
		to_bit_interleavingG(&t0, U64BIG32G(*(u64*)ad));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		adlen -= ISAP_rH / 8;
		ad += ISAP_rH / 8;
		P_sHG;
	}

	// Absorb partial lane of AD and add padding
	if (adlen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;
		for (i = 0; i < adlen; i++)
		{
			tmp0_bytes[i] = *ad;
			ad += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleavingG(&t0, U64BIG32G(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG;
	}

	// Absorb AD padding if not already done before
	if (adlen == 0)
	{
		x0.o ^= 0x80000000;
		P_sHG;
	}

	// Domain Seperation
	x4.e ^= ((u32)0x01);

	// Absorb full lanes of C
	while (clen >= 8)
	{
		to_bit_interleavingG(&t0, U64BIG32G(*(u64*)c));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG;
		clen -= ISAP_rH / 8;
		c += ISAP_rH / 8;
	}

	// Absorb partial lane of C and add padding
	if (clen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;
		for (i = 0; i < clen; i++)
		{
			tmp0_bytes[i] = *c;
			c += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleavingG(&t0, U64BIG32G(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG;
	}

	// Absorb C padding if not already done before
	if (clen == 0)
	{
		x0.o ^= 0x80000000;
		P_sHG;
	}

	// Finalize - Derive Ka*
	u64 y64[CRYPTO_KEYBYTES / 8];
	from_bit_interleavingG(&tmp0, x0);
	y64[0] = U64BIG32G(tmp0);
	from_bit_interleavingG(&tmp0, x1);
	y64[1] = U64BIG32G(tmp0);
	u32 ka_star32[CRYPTO_KEYBYTES / 4];
	isap_rk_O32G(k, ISAP_IV1G, (u8*)y64, (u8*)ka_star32, CRYPTO_KEYBYTES);

	// Finalize - Squeeze T
	x0.o = ka_star32[0];
	x0.e = ka_star32[1];
	x1.o = ka_star32[2];
	x1.e = ka_star32[3];
	P_sHG;
	from_bit_interleavingG(&tmp0, x0);
	*(u64*)(tag + 0) = U64BIG32G(tmp0);
	from_bit_interleavingG(&tmp0, x1);
	*(u64*)(tag + 8) = U64BIG32G(tmp0);
}


///////// Op32 Optimised
__device__ const u32 rc_oG_32Op[12] = { 0xc, 0xc, 0x9, 0x9, 0xc, 0xc, 0x9, 0x9, 0x6, 0x6, 0x3, 0x3 };	//optimise here
__device__ const u32 rc_eG_32Op[12] = { 0xc, 0x9, 0xc, 0x9, 0x6, 0x3, 0x6, 0x3, 0xc, 0x9, 0xc, 0x9 };	//optimise here

#include <math.h>
__device__ void static inline PXG_Op32(u32 rounds, u32_2* x0, u32_2* x1, u32_2* x2, u32_2* x3, u32_2* x4) {
	u32 t0e, t1e, t2e, t3e, t4e;
	u32 t0o, t1o, t2o, t3o, t4o;

#pragma unroll		//here
	for (u32 r = 12 - rounds; r < 12; r++) {

		/* rcon */
		(*x2).e ^= rc_eG_32Op[r];
		(*x2).o ^= rc_oG_32Op[r];
		/* non-linear layer */
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		(*x4).e ^= (*x3).e;
		(*x4).o ^= (*x3).o;
		(*x2).e ^= (*x1).e;
		(*x2).o ^= (*x1).o;
		t0e = (*x0).e;
		t0o = (*x0).o;
		t4e = (*x4).e;
		t4o = (*x4).o;
		t3e = (*x3).e;
		t3o = (*x3).o;
		t1e = (*x1).e;
		t1o = (*x1).o;
		t2e = (*x2).e;
		t2o = (*x2).o;
		(*x0).e = t0e ^ (~t1e & t2e);
		(*x0).o = t0o ^ (~t1o & t2o);
		(*x2).e = t2e ^ (~t3e & t4e);
		(*x2).o = t2o ^ (~t3o & t4o);
		(*x4).e = t4e ^ (~t0e & t1e);
		(*x4).o = t4o ^ (~t0o & t1o);
		(*x1).e = t1e ^ (~t2e & t3e);
		(*x1).o = t1o ^ (~t2o & t3o);
		(*x3).e = t3e ^ (~t4e & t0e);
		(*x3).o = t3o ^ (~t4o & t0o);
		(*x1).e ^= (*x0).e;
		(*x1).o ^= (*x0).o;
		(*x3).e ^= (*x2).e;
		(*x3).o ^= (*x2).o;
		(*x0).e ^= (*x4).e;
		(*x0).o ^= (*x4).o;
		/* linear layer */
		t0e = (*x0).e ^ ROTR32((*x0).o, 4);
		t0o = (*x0).o ^ ROTR32((*x0).e, 5);
		t1e = (*x1).e ^ ROTR32((*x1).e, 11);
		t1o = (*x1).o ^ ROTR32((*x1).o, 11);
		t2e = (*x2).e ^ ROTR32((*x2).o, 2);
		t2o = (*x2).o ^ ROTR32((*x2).e, 3);
		t3e = (*x3).e ^ ROTR32((*x3).o, 3);
		t3o = (*x3).o ^ ROTR32((*x3).e, 4);
		t4e = (*x4).e ^ ROTR32((*x4).e, 17);
		t4o = (*x4).o ^ ROTR32((*x4).o, 17);
		(*x0).e ^= ROTR32(t0o, 9);
		(*x0).o ^= ROTR32(t0e, 10);
		(*x1).e ^= ROTR32(t1o, 19);
		(*x1).o ^= ROTR32(t1e, 20);
		(*x2).e ^= t2o;
		(*x2).o ^= ROTR32(t2e, 1);
		(*x3).e ^= ROTR32(t3e, 5);
		(*x3).o ^= ROTR32(t3o, 5);
		(*x4).e ^= ROTR32(t4o, 3);
		(*x4).o ^= ROTR32(t4e, 4);
		(*x2).e = ~(*x2).e;
		(*x2).o = ~(*x2).o;
	}
}

#define P_sBG_Op PXG_Op32(12,&x0,&x1,&x2,&x3,&x4)
#define P_sEG_Op PXG_Op32(12,&x0,&x1,&x2,&x3,&x4)
#define P_sHG_Op PXG_Op32(12,&x0,&x1,&x2,&x3,&x4)
#define P_sKG_Op PXG_Op32(12,&x0,&x1,&x2,&x3,&x4)

__device__ void isap_rk_O32G_Op(
	const u8* k,
	const u8* iv,
	const u8* y,
	u8* out,
	const u8 outlen)
{
	// State variables
	u32_2 x0, x1, x2, x3, x4;

	// Initialize
	to_bit_interleavingG(&x0, U64BIG32G(*(u64*)(k + 0)));
	to_bit_interleavingG(&x1, U64BIG32G(*(u64*)(k + 8)));
	to_bit_interleavingG(&x2, U64BIG32G(*(u64*)(iv + 0)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sKG_Op;

	// Absorb Y, bit by bit
	for (u8 i = 0; i < 127; i++) {
		u8 cur_byte_pos = i / 8;
		u8 cur_bit_pos = 7 - (i % 8);
		u32 cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
		x0.o ^= ((u32)cur_bit) << 24;
		P_sBG_Op;
	}
	u8 cur_bit = ((y[15]) & 0x01) << 7;
	x0.o ^= ((u32)cur_bit) << (24);

	// Squeeze - Derive K*
	P_sKG_Op;
	*(u32*)(out + 0) = x0.o;
	*(u32*)(out + 4) = x0.e;
	*(u32*)(out + 8) = x1.o;
	*(u32*)(out + 12) = x1.e;
	if (outlen > 16) {
		*(u32*)(out + 16) = x2.o;
		*(u32*)(out + 20) = x2.e;
	}
}

__device__ void isap_mac_O32G_Op(
	const u8 * k,
	const u8 * npub,
	const u8 * ad, u64 adlen,
	const u8 * c, u64 clen,
	u8 * tag)
{
	// State and temporary variables
	u32_2 x0, x1, x2, x3, x4;
	u32_2 t0;
	u64 tmp0;

	// Initialize
	to_bit_interleavingG(&x0, U64BIG32G(*(u64*)npub + 0));
	to_bit_interleavingG(&x1, U64BIG32G(*(u64*)(npub + 8)));
	to_bit_interleavingG(&x2, U64BIG32G(*(u64*)(ISAP_IV1G)));
	x3.o = 0;
	x3.e = 0;
	x4.o = 0;
	x4.e = 0;
	P_sHG_Op;

	// Absorb full lanes of AD
	while (adlen >= 8)
	{
		to_bit_interleavingG(&t0, U64BIG32G(*(u64*)ad));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		adlen -= ISAP_rH / 8;
		ad += ISAP_rH / 8;
		P_sHG_Op;
	}

	// Absorb partial lane of AD and add padding
	if (adlen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;

		for (i = 0; i < adlen; i++)
		{
			tmp0_bytes[i] = *ad;
			ad += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleavingG(&t0, U64BIG32G(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG_Op;
	}

	// Absorb AD padding if not already done before
	if (adlen == 0)
	{
		x0.o ^= 0x80000000;
		P_sHG_Op;
	}

	// Domain Seperation
	x4.e ^= ((u32)0x01);

	// Absorb full lanes of C
	while (clen >= 8)
	{
		to_bit_interleavingG(&t0, U64BIG32G(*(u64*)c));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG_Op;
		clen -= ISAP_rH / 8;
		c += ISAP_rH / 8;
	}

	// Absorb partial lane of C and add padding
	if (clen > 0)
	{
		tmp0 = 0;
		u8* tmp0_bytes = (u8*)& tmp0;
		u8 i;

		for (i = 0; i < clen; i++)
		{
			tmp0_bytes[i] = *c;
			c += 1;
		}
		tmp0_bytes[i] = 0x80;
		to_bit_interleavingG(&t0, U64BIG32G(tmp0));
		x0.e ^= t0.e;
		x0.o ^= t0.o;
		P_sHG_Op;
	}

	// Absorb C padding if not already done before
	if (clen == 0)
	{
		x0.o ^= 0x80000000;
		P_sHG_Op;
	}

	// Finalize - Derive Ka*
	u64 y64[CRYPTO_KEYBYTES / 8];
	from_bit_interleavingG(&tmp0, x0);
	y64[0] = U64BIG32G(tmp0);
	from_bit_interleavingG(&tmp0, x1);
	y64[1] = U64BIG32G(tmp0);
	u32 ka_star32[CRYPTO_KEYBYTES / 4];
	isap_rk_O32G_Op(k, ISAP_IV1G, (u8*)y64, (u8*)ka_star32, CRYPTO_KEYBYTES);

	// Finalize - Squeeze T
	x0.o = ka_star32[0];
	x0.e = ka_star32[1];
	x1.o = ka_star32[2];
	x1.e = ka_star32[3];
	P_sHG_Op;
	from_bit_interleavingG(&tmp0, x0);
	*(u64*)(tag + 0) = U64BIG32G(tmp0);
	from_bit_interleavingG(&tmp0, x1);
	*(u64*)(tag + 8) = U64BIG32G(tmp0);
}

