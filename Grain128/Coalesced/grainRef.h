#include <stdlib.h>
#include <string.h>
#include "params.h"

enum GRAIN_ROUND { INIT, ADDKEY, NORMAL };

typedef struct {
	unsigned char lfsr[128];
	unsigned char nfsr[128];
	unsigned char auth_acc[64];
	unsigned char auth_sr[64];
} grain_state;

typedef struct {
	unsigned char* message;
	unsigned long long msg_len;
} grain_data;

unsigned char grain_round;

unsigned char swapsb(unsigned char n);

unsigned char next_lfsr_fb(grain_state* grain)
{
	/* f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128 */
	return grain->lfsr[96] ^ grain->lfsr[81] ^ grain->lfsr[70] ^ grain->lfsr[38] ^ grain->lfsr[7] ^ grain->lfsr[0];
}

unsigned char next_nfsr_fb(grain_state* grain)
{
	return grain->nfsr[96] ^ grain->nfsr[91] ^ grain->nfsr[56] ^ grain->nfsr[26] ^ grain->nfsr[0] ^ (grain->nfsr[84] & grain->nfsr[68]) ^
		(grain->nfsr[67] & grain->nfsr[3]) ^ (grain->nfsr[65] & grain->nfsr[61]) ^ (grain->nfsr[59] & grain->nfsr[27]) ^
		(grain->nfsr[48] & grain->nfsr[40]) ^ (grain->nfsr[18] & grain->nfsr[17]) ^ (grain->nfsr[13] & grain->nfsr[11]) ^
		(grain->nfsr[82] & grain->nfsr[78] & grain->nfsr[70]) ^ (grain->nfsr[25] & grain->nfsr[24] & grain->nfsr[22]) ^
		(grain->nfsr[95] & grain->nfsr[93] & grain->nfsr[92] & grain->nfsr[88]);
}

unsigned char next_h(grain_state* grain)
{
	// h(x) = x0x1 + x2x3 + x4x5 + x6x7 + x0x4x8
#define x0 grain->nfsr[12]	// bi+12
#define x1 grain->lfsr[8]		// si+8
#define x2 grain->lfsr[13]	// si+13
#define x3 grain->lfsr[20]	// si+20
#define x4 grain->nfsr[95]	// bi+95
#define x5 grain->lfsr[42]	// si+42
#define x6 grain->lfsr[60]	// si+60
#define x7 grain->lfsr[79]	// si+79
#define x8 grain->lfsr[94]	// si+94

	unsigned char h_out = (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
	return h_out;
}

unsigned char shift(unsigned char fsr[128], unsigned char fb)
{
	unsigned char out = fsr[0];
	for (int i = 0; i < 127; i++) {
		fsr[i] = fsr[i + 1];
	}
	fsr[127] = fb;

	return out;
}

unsigned char next_z(grain_state* grain, unsigned char keybit, unsigned char keybit_64)
{
	unsigned char lfsr_fb = next_lfsr_fb(grain);
	unsigned char nfsr_fb = next_nfsr_fb(grain);
	unsigned char h_out = next_h(grain);

	/* y = h + s_{i+93} + sum(b_{i+j}), j \in A */
	unsigned char A[] = { 2, 15, 36, 45, 64, 73, 89 };

	unsigned char nfsr_tmp = 0;
	for (int i = 0; i < 7; i++) {
		nfsr_tmp ^= grain->nfsr[A[i]];
	}

	unsigned char y = h_out ^ grain->lfsr[93] ^ nfsr_tmp;

	unsigned char lfsr_out;

	/* feedback y if we are in the initialization instance */
	if (grain_round == INIT) {
		lfsr_out = shift(grain->lfsr, lfsr_fb ^ y);
		shift(grain->nfsr, nfsr_fb ^ lfsr_out ^ y);
	}
	else if (grain_round == ADDKEY) {
		lfsr_out = shift(grain->lfsr, lfsr_fb ^ y ^ keybit_64);
		shift(grain->nfsr, nfsr_fb ^ lfsr_out ^ y ^ keybit);
	}
	else if (grain_round == NORMAL) {
		lfsr_out = shift(grain->lfsr, lfsr_fb);
		shift(grain->nfsr, nfsr_fb ^ lfsr_out);
	}

	return y;
}

void init_grain(grain_state* grain, const unsigned char* key, const unsigned char* iv)
{
	unsigned char key_bits[128];
	unsigned char iv_bits[96];

	// expand the packed bytes and place one bit per array cell (like a flip flop in HW)
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 8; j++) {
			key_bits[8 * i + j] = (key[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	for (int i = 0; i < 12; i++) {
		for (int j = 0; j < 8; j++) {
			iv_bits[8 * i + j] = (iv[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	/* set up LFSR */
	for (int i = 0; i < 96; i++) {
		grain->lfsr[i] = iv_bits[i];
	}

	for (int i = 96; i < 127; i++) {
		grain->lfsr[i] = 1;
	}

	grain->lfsr[127] = 0;

	/* set up NFSR */
	for (int i = 0; i < 128; i++) {
		grain->nfsr[i] = key_bits[i];
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = 0;
		grain->auth_sr[i] = 0;
	}

	/* initialize grain and skip output */
	grain_round = INIT;
	for (int i = 0; i < 320; i++) {
		next_z(grain, 0, 0);
	}

	grain_round = ADDKEY;

	/* re-introduce the key into LFSR and NFSR in parallel during the next 64 clocks */
	for (int i = 0; i < 64; i++) {
		unsigned char addkey_0 = key_bits[i];
		unsigned char addkey_64 = key_bits[64 + i];
		next_z(grain, addkey_0, addkey_64);
	}

	grain_round = NORMAL;

	/* inititalize the accumulator and shift register */
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = next_z(grain, 0, 0);
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_sr[i] = next_z(grain, 0, 0);
	}
}

void init_data(grain_data* data, const unsigned char* msg, unsigned long long msg_len)
{
	// allocate enough space for message, including the padding bit 1 (byte 0x80)
	data->message = (unsigned char*)calloc(8 * msg_len + 1, 1);
	data->msg_len = 8 * msg_len + 1;
	for (unsigned long long i = 0; i < msg_len; i++) {
		for (int j = 0; j < 8; j++) {
			data->message[8 * i + j] = (msg[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	// always pad data with the bit 1 (byte 0x80)
	data->message[data->msg_len - 1] = 1;
}

void auth_shift(unsigned char sr[64], unsigned char fb)
{
	for (int i = 0; i < 63; i++) {
		sr[i] = sr[i + 1];
	}
	sr[63] = fb;
}

void accumulate(grain_state* grain)
{
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] ^= grain->auth_sr[i];
	}
}



int encode_der(unsigned long long len, unsigned char** der)
{
	unsigned long long len_tmp;
	int der_len = 0;

	if (len < 128) {
		*der = (unsigned char*)malloc(1);
		(*der)[0] = swapsb((unsigned char)len);
		return 1;
	}

	len_tmp = len;
	do {
		len_tmp >>= 8;
		der_len++;
	} while (len_tmp != 0);

	// one extra byte to describe the number of bytes used
	*der = (unsigned char*)malloc(der_len + 1);
	(*der)[0] = swapsb(0x80 | der_len);

	len_tmp = len;
	for (int i = der_len; i > 0; i--) {
		(*der)[i] = swapsb(len_tmp & 0xff);
		len_tmp >>= 8;
	}

	return der_len + 1;
}

unsigned char swapsb(unsigned char n)
{
	// swaps significant bit
	unsigned char val = 0;
	for (int i = 0; i < 8; i++) {
		val |= ((n >> i) & 1) << (7 - i);
	}
	return val;
}

////////////////////////////////////////////////////////////////////////////
/*								GPU   Reference							*/
////////////////////////////////////////////////////////////////////////////

__device__ unsigned char grain_roundG;

__device__ unsigned char swapsbG(unsigned char n);

__device__ unsigned char next_lfsr_fbG(grain_state* grain)
{
	/* f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128 */
	return grain->lfsr[96] ^ grain->lfsr[81] ^ grain->lfsr[70] ^ grain->lfsr[38] ^ grain->lfsr[7] ^ grain->lfsr[0];
}

__device__ unsigned char next_nfsr_fbG(grain_state* grain)
{
	return grain->nfsr[96] ^ grain->nfsr[91] ^ grain->nfsr[56] ^ grain->nfsr[26] ^ grain->nfsr[0] ^ (grain->nfsr[84] & grain->nfsr[68]) ^
		(grain->nfsr[67] & grain->nfsr[3]) ^ (grain->nfsr[65] & grain->nfsr[61]) ^ (grain->nfsr[59] & grain->nfsr[27]) ^
		(grain->nfsr[48] & grain->nfsr[40]) ^ (grain->nfsr[18] & grain->nfsr[17]) ^ (grain->nfsr[13] & grain->nfsr[11]) ^
		(grain->nfsr[82] & grain->nfsr[78] & grain->nfsr[70]) ^ (grain->nfsr[25] & grain->nfsr[24] & grain->nfsr[22]) ^
		(grain->nfsr[95] & grain->nfsr[93] & grain->nfsr[92] & grain->nfsr[88]);
}

__device__ unsigned char next_hG(grain_state* grain)
{
	// h(x) = x0x1 + x2x3 + x4x5 + x6x7 + x0x4x8
#define x0G grain->nfsr[12]	// bi+12
#define x1G grain->lfsr[8]		// si+8
#define x2G grain->lfsr[13]	// si+13
#define x3G grain->lfsr[20]	// si+20
#define x4G grain->nfsr[95]	// bi+95
#define x5G grain->lfsr[42]	// si+42
#define x6G grain->lfsr[60]	// si+60
#define x7G grain->lfsr[79]	// si+79
#define x8G grain->lfsr[94]	// si+94

	unsigned char h_out = (x0G & x1G) ^ (x2G & x3G) ^ (x4G & x5G) ^ (x6G & x7G) ^ (x0G & x4G & x8G);
	return h_out;
}

//fine grain
__device__ unsigned char shiftG(unsigned char fsr[128], unsigned char fb)
{
	unsigned char out = fsr[0];

	for (int i = 0; i < 127; i++) {
		fsr[i] = fsr[i + 1];
	}
	fsr[127] = fb;

	return out;
}

__device__ unsigned char next_zG(grain_state* grain, unsigned char keybit, unsigned char keybit_64)
{
	unsigned char lfsr_fb = next_lfsr_fbG(grain);
	unsigned char nfsr_fb = next_nfsr_fbG(grain);
	unsigned char h_out = next_hG(grain);

	/* y = h + s_{i+93} + sum(b_{i+j}), j \in A */
	unsigned char A[] = { 2, 15, 36, 45, 64, 73, 89 };

	unsigned char nfsr_tmp = 0;
	for (int i = 0; i < 7; i++) {
		nfsr_tmp ^= grain->nfsr[A[i]];
	}

	unsigned char y = h_out ^ grain->lfsr[93] ^ nfsr_tmp;

	unsigned char lfsr_out;

	/* feedback y if we are in the initialization instance */
	if (grain_roundG == INIT) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb ^ y);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out ^ y);
	}
	else if (grain_roundG == ADDKEY) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb ^ y ^ keybit_64);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out ^ y ^ keybit);
	}
	else if (grain_roundG == NORMAL) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out);
	}

	return y;
}

//fine grain, shared memory
__device__ void init_grainG(grain_state* grain, const unsigned char* key, const unsigned char* iv)
{
	unsigned char key_bits[128];
	unsigned char iv_bits[96];

	// expand the packed bytes and place one bit per array cell (like a flip flop in HW)
	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < 8; j++) {
			key_bits[8 * i + j] = (key[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	for (int i = 0; i < 12; i++) {
		for (int j = 0; j < 8; j++) {
			iv_bits[8 * i + j] = (iv[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	/* set up LFSR */
	for (int i = 0; i < 96; i++) {
		grain->lfsr[i] = iv_bits[i];
	}

	for (int i = 96; i < 127; i++) {
		grain->lfsr[i] = 1;
	}

	grain->lfsr[127] = 0;

	/* set up NFSR */
	for (int i = 0; i < 128; i++) {
		grain->nfsr[i] = key_bits[i];
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = 0;
		grain->auth_sr[i] = 0;
	}

	/* initialize grain and skip output */
	grain_roundG = INIT;
	for (int i = 0; i < 320; i++) {
		next_zG(grain, 0, 0);
	}

	grain_roundG = ADDKEY;

	/* re-introduce the key into LFSR and NFSR in parallel during the next 64 clocks */
	for (int i = 0; i < 64; i++) {
		unsigned char addkey_0 = key_bits[i];
		unsigned char addkey_64 = key_bits[64 + i];
		next_zG(grain, addkey_0, addkey_64);
	}

	grain_roundG = NORMAL;

	/* inititalize the accumulator and shift register */
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = next_zG(grain, 0, 0);
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_sr[i] = next_zG(grain, 0, 0);
	}
}

//fine grain
__device__ void init_dataG(grain_data* data, const unsigned char* msg, unsigned long long msg_len)
{
	// allocate enough space for message, including the padding bit 1 (byte 0x80)
	data->message = (unsigned char*)malloc((8 * msg_len + 1) * 1);

	data->msg_len = 8 * msg_len + 1;
	for (unsigned long long i = 0; i < msg_len; i++) {
		for (int j = 0; j < 8; j++) {
			data->message[8 * i + j] = (msg[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	// always pad data with the bit 1 (byte 0x80)
	data->message[data->msg_len - 1] = 1;
}

//fine grain
__device__ void auth_shiftG(unsigned char sr[64], unsigned char fb)
{
	for (int i = 0; i < 63; i++) {
		sr[i] = sr[i + 1];
	}
	sr[63] = fb;
}

//fine grain
__device__ void accumulateG(grain_state* grain)
{
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] ^= grain->auth_sr[i];
	}
}

__device__ unsigned char swapsbG(unsigned char n)
{
	// swaps significant bit
	unsigned char val = 0;
	for (int i = 0; i < 8; i++) {
		val |= ((n >> i) & 1) << (7 - i);
	}
	return val;
}

__device__ int encode_derG(unsigned long long len, unsigned char** der)
{
	unsigned long long len_tmp;
	int der_len = 0;

	if (len < 128) {
		*der = (unsigned char*)malloc(1);
		(*der)[0] = swapsbG((unsigned char)len);
		return 1;
	}

	len_tmp = len;
	do {
		len_tmp >>= 8;
		der_len++;
	} while (len_tmp != 0);

	// one extra byte to describe the number of bytes used
	*der = (unsigned char*)malloc(der_len + 1);
	(*der)[0] = swapsbG(0x80 | der_len);

	len_tmp = len;
	for (int i = der_len; i > 0; i--) {
		(*der)[i] = swapsbG(len_tmp & 0xff);
		len_tmp >>= 8;
	}

	return der_len + 1;
}


////////////////////////////////////////////////////////////////////////////
/*								ShareMem Optimisation			          */
////////////////////////////////////////////////////////////////////////////

#define next_lfsr_fb_Op() \
	grain->lfsr[96] ^ grain->lfsr[81] ^ grain->lfsr[70] ^ grain->lfsr[38] ^ grain->lfsr[7] ^ grain->lfsr[0];


#define next_nfsr_fb_Op() \
	 grain->nfsr[96] ^ grain->nfsr[91] ^ grain->nfsr[56] ^ grain->nfsr[26] ^ grain->nfsr[0] ^ (grain->nfsr[84] & grain->nfsr[68]) ^ \
	(grain->nfsr[67] & grain->nfsr[3]) ^ (grain->nfsr[65] & grain->nfsr[61]) ^ (grain->nfsr[59] & grain->nfsr[27]) ^ \
	(grain->nfsr[48] & grain->nfsr[40]) ^ (grain->nfsr[18] & grain->nfsr[17]) ^ (grain->nfsr[13] & grain->nfsr[11]) ^ \
	(grain->nfsr[82] & grain->nfsr[78] & grain->nfsr[70]) ^ (grain->nfsr[25] & grain->nfsr[24] & grain->nfsr[22]) ^ \
	(grain->nfsr[95] & grain->nfsr[93] & grain->nfsr[92] & grain->nfsr[88]);

__device__ unsigned char next_zG_MemOp(grain_state* grain, unsigned char keybit, unsigned char keybit_64)
{
	unsigned char lfsr_fb = next_lfsr_fb_Op();
	unsigned char nfsr_fb = next_nfsr_fb_Op();
	unsigned char h_out = next_hG(grain);

	/* y = h + s_{i+93} + sum(b_{i+j}), j \in A */
	//unsigned char A[] = { 2, 15, 36, 45, 64, 73, 89 };

	unsigned char nfsr_tmp = 0;

	nfsr_tmp ^= grain->nfsr[2];
	nfsr_tmp ^= grain->nfsr[15];
	nfsr_tmp ^= grain->nfsr[36];
	nfsr_tmp ^= grain->nfsr[45];
	nfsr_tmp ^= grain->nfsr[64];
	nfsr_tmp ^= grain->nfsr[73];
	nfsr_tmp ^= grain->nfsr[89];

	unsigned char y = h_out ^ grain->lfsr[93] ^ nfsr_tmp;

	unsigned char lfsr_out;

	/* feedback y if we are in the initialization instance */
	if (grain_roundG == INIT) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb ^ y);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out ^ y);
	}
	else if (grain_roundG == ADDKEY) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb ^ y ^ keybit_64);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out ^ y ^ keybit);
	}
	else if (grain_roundG == NORMAL) {
		lfsr_out = shiftG(grain->lfsr, lfsr_fb);
		shiftG(grain->nfsr, nfsr_fb ^ lfsr_out);
	}

	return y;
}

__device__ void init_grain_MemOp(grain_state* grain, const unsigned char* key, const unsigned char* iv)
{
	unsigned char key_bits[128];
	unsigned char iv_bits[96];

	for (int i = 0; i < 16; i++) {
		key_bits[8 * i + 0] = (key[i] & (1 << (7 - 0))) >> (7 - 0);
		key_bits[8 * i + 1] = (key[i] & (1 << (7 - 1))) >> (7 - 1);
		key_bits[8 * i + 2] = (key[i] & (1 << (7 - 2))) >> (7 - 2);
		key_bits[8 * i + 3] = (key[i] & (1 << (7 - 3))) >> (7 - 3);
		key_bits[8 * i + 4] = (key[i] & (1 << (7 - 4))) >> (7 - 4);
		key_bits[8 * i + 5] = (key[i] & (1 << (7 - 5))) >> (7 - 5);
		key_bits[8 * i + 6] = (key[i] & (1 << (7 - 6))) >> (7 - 6);
		key_bits[8 * i + 7] = (key[i] & (1 << (7 - 7))) >> (7 - 7);
	}

	//unroll
#pragma unroll
	for (int i = 0; i < 12; i++) {
		iv_bits[8 * i + 0] = (iv[i] & (1 << (7 - 0))) >> (7 - 0);
		iv_bits[8 * i + 1] = (iv[i] & (1 << (7 - 1))) >> (7 - 1);
		iv_bits[8 * i + 2] = (iv[i] & (1 << (7 - 2))) >> (7 - 2);
		iv_bits[8 * i + 3] = (iv[i] & (1 << (7 - 3))) >> (7 - 3);
		iv_bits[8 * i + 4] = (iv[i] & (1 << (7 - 4))) >> (7 - 4);
		iv_bits[8 * i + 5] = (iv[i] & (1 << (7 - 5))) >> (7 - 5);
		iv_bits[8 * i + 6] = (iv[i] & (1 << (7 - 6))) >> (7 - 6);
		iv_bits[8 * i + 7] = (iv[i] & (1 << (7 - 7))) >> (7 - 7);
	}

	/* set up LFSR */
	for (int i = 0; i < 96; i++) {
		grain->lfsr[i] = iv_bits[i];
	}

	for (int i = 96; i < 127; i++) {
		grain->lfsr[i] = 1;
	}

	grain->lfsr[127] = 0;

	/* set up NFSR */
	for (int i = 0; i < 128; i++) {
		grain->nfsr[i] = key_bits[i];
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = 0;
		grain->auth_sr[i] = 0;
	}

	/* initialize grain and skip output */
	grain_roundG = INIT;

	for (int i = 0; i < 320; i++) {
		next_zG_MemOp(grain, 0, 0);
	}

	grain_roundG = ADDKEY;

	/* re-introduce the key into LFSR and NFSR in parallel during the next 64 clocks */
	for (int i = 0; i < 64; i++) {
		unsigned char addkey_0 = key_bits[i];
		unsigned char addkey_64 = key_bits[64 + i];
		next_zG_MemOp(grain, addkey_0, addkey_64);
	}

	grain_roundG = NORMAL;

	/* inititalize the accumulator and shift register */
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = next_zG_MemOp(grain, 0, 0);
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_sr[i] = next_zG_MemOp(grain, 0, 0);
	}
}


////////////////////////////////////////////////////////////////////////////
/*								FineGrain Optimisation			          */
////////////////////////////////////////////////////////////////////////////

__device__ unsigned char shift_Fine(unsigned char fsr[128], unsigned char fb)
{
	unsigned char out = fsr[0];

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)127 / (double)fineLevel)));
	int e = (c + ceil(((double)127 / (double)fineLevel)));
	e = (e > 127) ? 127 : e;

	for (int i = c; i < e; i++) {
		fsr[i] = fsr[i + 1];
	}
	fsr[127] = fb;
	__syncthreads();

	return out;
}

__device__ void auth_shiftG_Fine(unsigned char sr[64], unsigned char fb)
{

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)63 / (double)fineLevel)));
	int e = (c + ceil(((double)63 / (double)fineLevel)));
	e = (e > 63) ? 63 : e;

	for (int i = c; i < e; i++) {
		sr[i] = sr[i + 1];
	}
	sr[63] = fb;
}

//fine grain
__device__ void accumulateG_Fine(grain_state* grain)
{
	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)64 / (double)fineLevel)));
	int e = (c + ceil(((double)64 / (double)fineLevel)));
	e = (e > 16) ? 16 : e;

	for (int i = c; i < e; i++) {
		grain->auth_acc[i] ^= grain->auth_sr[i];
	}
}


__device__ unsigned char next_zG_Fine(grain_state* grain, unsigned char keybit, unsigned char keybit_64)
{
	unsigned char lfsr_fb = next_lfsr_fb_Op();
	unsigned char nfsr_fb = next_nfsr_fb_Op();
	unsigned char h_out = next_hG(grain);

	/* y = h + s_{i+93} + sum(b_{i+j}), j \in A */
	//unsigned char A[] = { 2, 15, 36, 45, 64, 73, 89 };

	unsigned char nfsr_tmp = 0;

	nfsr_tmp ^= grain->nfsr[2];
	nfsr_tmp ^= grain->nfsr[15];
	nfsr_tmp ^= grain->nfsr[36];
	nfsr_tmp ^= grain->nfsr[45];
	nfsr_tmp ^= grain->nfsr[64];
	nfsr_tmp ^= grain->nfsr[73];
	nfsr_tmp ^= grain->nfsr[89];

	unsigned char y = h_out ^ grain->lfsr[93] ^ nfsr_tmp;

	unsigned char lfsr_out;

	/* feedback y if we are in the initialization instance */
	if (grain_roundG == INIT) {
		lfsr_out = shift_Fine(grain->lfsr, lfsr_fb ^ y);
		shift_Fine(grain->nfsr, nfsr_fb ^ lfsr_out ^ y);
	}
	else if (grain_roundG == ADDKEY) {
		lfsr_out = shift_Fine(grain->lfsr, lfsr_fb ^ y ^ keybit_64);
		shift_Fine(grain->nfsr, nfsr_fb ^ lfsr_out ^ y ^ keybit);
	}
	else if (grain_roundG == NORMAL) {
		lfsr_out = shift_Fine(grain->lfsr, lfsr_fb);
		shift_Fine(grain->nfsr, nfsr_fb ^ lfsr_out);
	}

	return y;
}

__device__ void init_grain_Fine(grain_state* grain, const unsigned char* key, const unsigned char* iv)
{
	__shared__ unsigned char key_bits[128];
	__shared__ unsigned char iv_bits[96];

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)16 / (double)fineLevel)));
	int e = (c + ceil(((double)16 / (double)fineLevel)));
	e = (e > 16) ? 16 : e; //prevent overload

	for (int i = c; i < e; i++) {
		key_bits[8 * i + 0] = (key[i] & (1 << (7 - 0))) >> (7 - 0);
		key_bits[8 * i + 1] = (key[i] & (1 << (7 - 1))) >> (7 - 1);
		key_bits[8 * i + 2] = (key[i] & (1 << (7 - 2))) >> (7 - 2);
		key_bits[8 * i + 3] = (key[i] & (1 << (7 - 3))) >> (7 - 3);
		key_bits[8 * i + 4] = (key[i] & (1 << (7 - 4))) >> (7 - 4);
		key_bits[8 * i + 5] = (key[i] & (1 << (7 - 5))) >> (7 - 5);
		key_bits[8 * i + 6] = (key[i] & (1 << (7 - 6))) >> (7 - 6);
		key_bits[8 * i + 7] = (key[i] & (1 << (7 - 7))) >> (7 - 7);
	}

	//unroll
#pragma unroll
	c = (innertid * fineLevel * ceil(((double)12 / (double)fineLevel)));
	e = (c + ceil(((double)12 / (double)fineLevel)));
	e = (e > 12) ? 12 : e; //prevent overload

	for (int i = c; i < e; i++) {
		iv_bits[8 * i + 0] = (iv[i] & (1 << (7 - 0))) >> (7 - 0);
		iv_bits[8 * i + 1] = (iv[i] & (1 << (7 - 1))) >> (7 - 1);
		iv_bits[8 * i + 2] = (iv[i] & (1 << (7 - 2))) >> (7 - 2);
		iv_bits[8 * i + 3] = (iv[i] & (1 << (7 - 3))) >> (7 - 3);
		iv_bits[8 * i + 4] = (iv[i] & (1 << (7 - 4))) >> (7 - 4);
		iv_bits[8 * i + 5] = (iv[i] & (1 << (7 - 5))) >> (7 - 5);
		iv_bits[8 * i + 6] = (iv[i] & (1 << (7 - 6))) >> (7 - 6);
		iv_bits[8 * i + 7] = (iv[i] & (1 << (7 - 7))) >> (7 - 7);
	}

	__syncthreads();
	c = (innertid * fineLevel * ceil(((double)96 / (double)fineLevel)));
	e = (c + ceil(((double)96 / (double)fineLevel)));
	e = (e > 96) ? 96 : e; //prevent overload

	/* set up LFSR */
	for (int i = c; i < e; i++) {
		grain->lfsr[i] = iv_bits[i];
	}

	__syncthreads();
	for (int i = 96; i < 127; i++) {
		grain->lfsr[i] = 1;
	}

	__syncthreads();

	grain->lfsr[127] = 0;

	/* set up NFSR */
	for (int i = 0; i < 128; i++) {
		grain->nfsr[i] = key_bits[i];
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = 0;
		grain->auth_sr[i] = 0;
	}

	/* initialize grain and skip output */
	grain_roundG = INIT;

	for (int i = 0; i < 320; i++) {
		next_zG_Fine(grain, 0, 0);
	}

	grain_roundG = ADDKEY;

	/* re-introduce the key into LFSR and NFSR in parallel during the next 64 clocks */
	for (int i = 0; i < 64; i++) {
		unsigned char addkey_0 = key_bits[i];
		unsigned char addkey_64 = key_bits[64 + i];
		next_zG_Fine(grain, addkey_0, addkey_64);
	}

	grain_roundG = NORMAL;

	/* inititalize the accumulator and shift register */
	for (int i = 0; i < 64; i++) {
		grain->auth_acc[i] = next_zG_Fine(grain, 0, 0);
	}

	for (int i = 0; i < 64; i++) {
		grain->auth_sr[i] = next_zG_Fine(grain, 0, 0);
	}
}

__device__ void init_data_Fine(grain_data* data, const unsigned char* msg, unsigned long long msg_len)
{
	// allocate enough space for message, including the padding bit 1 (byte 0x80)
	data->message = (unsigned char*)malloc((8 * msg_len + 1) * 1);

	data->msg_len = 8 * msg_len + 1;
	for (unsigned long long i = 0; i < msg_len; i++) {
		for (int j = 0; j < 8; j++) {
			data->message[8 * i + j] = (msg[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	// always pad data with the bit 1 (byte 0x80)
	data->message[data->msg_len - 1] = 1;
}
