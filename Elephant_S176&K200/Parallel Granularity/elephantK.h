#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"

/*******************************************************************************/
/*							     200 - Keccak    CPU                           */
/*******************************************************************************/


const BYTE KeccakRoundConstants[maxNrRounds] = {
	0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
	0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

const unsigned int KeccakRhoOffsets[nrLanes] = {
	0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};

void KeccakP200Round(BYTE* state, unsigned int indexRound)
{
	//theta
	unsigned int x, y;
	BYTE C[5], D[5];

	for (x = 0; x < 5; x++) {
		C[x] = 0;
		for (y = 0; y < 5; y++)
			C[x] ^= state[index(x, y)];
	}
	for (x = 0; x < 5; x++)
		D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(x, y)] ^= D[x];

	//rho
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsets[index(x, y)]);

	//pi
	BYTE tempA[25];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			tempA[index(x, y)] = state[index(x, y)];
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];

	//chi
	BYTE E[5];

	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++)
			E[x] = state[index(x, y)] ^ ((~state[index(x + 1, y)]) & state[index(x + 2, y)]);
		for (x = 0; x < 5; x++)
			state[index(x, y)] = E[x];
	}

	//iota
	state[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}

void permutationK(BYTE* state)
{
	for (unsigned int i = 0; i < maxNrRounds; i++)
		KeccakP200Round(state, i);
}


/*******************************************************************************/
/*									Encryption CPU                             */
/*******************************************************************************/

BYTE rotlK(BYTE b)
{
	return (b << 1) | (b >> 7);
}

int constcmpK(const BYTE* a, const BYTE* b, uint64_t length)
{
	BYTE r = 0;

	for (uint64_t i = 0; i < length; ++i)
		r |= a[i] ^ b[i];
	return r;
}

// State should be BLOCK_SIZE bytes long
// Note: input may be equal to output
void lfsr_stepK(BYTE* output, BYTE* input)
{
	//BYTE temp = rotl(input[0]) ^ (input[3] << 7) ^ (input[19] >> 7);  //different
	BYTE temp = rotlK(input[0]) ^ rotlK(input[2]) ^ (input[13] << 1);

	for (uint64_t i = 0; i < BLOCK_SIZE_K - 1; ++i)
		output[i] = input[i + 1];
	output[BLOCK_SIZE_K - 1] = temp;
}

void xor_blockK(BYTE* state, const BYTE* block, uint64_t size)
{
	for (uint64_t i = 0; i < size; ++i)
		state[i] ^= block[i];
}

// Write the ith assocated data block to "output".
// The nonce is prepended and padding is added as required.
// adlen is the length of the associated data in bytes
void get_ad_blockK(BYTE* output, const BYTE* ad, uint64_t adlen, const BYTE* npub, uint64_t i)
{
	uint64_t len = 0;
	// First block contains nonce
	// Remark: nonce may not be longer then BLOCK_SIZE
	if (i == 0) {
		memcpy(output, npub, CRYPTO_NPUBBYTES);
		len += CRYPTO_NPUBBYTES;
	}

	const uint64_t block_offset = i * BLOCK_SIZE_K - (i != 0) * CRYPTO_NPUBBYTES;
	// If adlen is divisible by BLOCK_SIZE, add an additional padding block
	if (i != 0 && block_offset == adlen) {
		memset(output, 0x00, BLOCK_SIZE_K);
		output[0] = 0x01;
		return;
	}
	const uint64_t r_outlen = BLOCK_SIZE_K - len;
	const uint64_t r_adlen = adlen - block_offset;
	// Fill with associated data if available
	if (r_outlen <= r_adlen) { // enough AD
		memcpy(output + len, ad + block_offset, r_outlen);
	}
	else { // not enough AD, need to pad
		if (r_adlen > 0) // ad might be nullptr
			memcpy(output + len, ad + block_offset, r_adlen);
		memset(output + len + r_adlen, 0x00, r_outlen - r_adlen);
		output[len + r_adlen] = 0x01;
	}
}

// Return the ith ciphertext block.
// clen is the length of the ciphertext in bytes 
void get_c_blockK(BYTE* output, const BYTE* c, uint64_t clen, uint64_t i)
{
	const uint64_t block_offset = i * BLOCK_SIZE_K;
	// If clen is divisible by BLOCK_SIZE, add an additional padding block
	if (block_offset == clen) {
		memset(output, 0x00, BLOCK_SIZE_K);
		output[0] = 0x01;
		return;
	}
	const uint64_t r_clen = clen - block_offset;
	// Fill with ciphertext if available
	if (BLOCK_SIZE_K <= r_clen) { // enough ciphertext
		memcpy(output, c + block_offset, BLOCK_SIZE_K);
	}
	else { // not enough ciphertext, need to pad
		if (r_clen > 0) // c might be nullptr
			memcpy(output, c + block_offset, r_clen);
		memset(output + r_clen, 0x00, BLOCK_SIZE_K - r_clen);
		output[r_clen] = 0x01;
	}
}





/*******************************************************************************/
/*							     200 - Keccak    GPU                           */
/*******************************************************************************/


__device__ const BYTE KeccakRoundConstantsG[maxNrRounds] = {
	0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
	0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

__device__ const unsigned int KeccakRhoOffsetsG[nrLanes] = {
	0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};


__device__ void KeccakP200RoundG(BYTE* state, unsigned int indexRound)
{
	//theta
	unsigned int x, y;
	BYTE C[5], D[5];

	for (x = 0; x < 5; x++) {
		C[x] = 0;
		for (y = 0; y < 5; y++)
			C[x] ^= state[index(x, y)];
	}
	for (x = 0; x < 5; x++)
		D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(x, y)] ^= D[x];

	//rho
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsetsG[index(x, y)]);

	//pi
	BYTE tempA[25];

#pragma unroll
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			tempA[index(x, y)] = state[index(x, y)];
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			state[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];

	//chi
	BYTE E[5];

	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++)
			E[x] = state[index(x, y)] ^ ((~state[index(x + 1, y)]) & state[index(x + 2, y)]);
		for (x = 0; x < 5; x++)
			state[index(x, y)] = E[x];
	}

	//iota
	state[index(0, 0)] ^= KeccakRoundConstantsG[indexRound];
}

__device__ void permutationKG(BYTE* state)
{
	for (unsigned int i = 0; i < maxNrRounds; i++) {
		KeccakP200RoundG(state, i);
		__syncthreads();
	}
}


/*******************************************************************************/
/*									Encryption GPU                             */
/*******************************************************************************/

__device__ BYTE rotlKG(BYTE b)
{
	return (b << 1) | (b >> 7);
}

__device__ int constcmpKG(const BYTE* a, const BYTE* b, uint64_t length)
{
	BYTE r = 0;

	for (uint64_t i = 0; i < length; ++i)
		r |= a[i] ^ b[i];
	return r;
}

// State should be BLOCK_SIZE bytes long
// Note: input may be equal to output
__device__ void lfsr_stepKG(BYTE* output, BYTE* input)
{
	BYTE temp = rotlKG(input[0]) ^ rotlKG(input[2]) ^ (input[13] << 1);

	for (uint64_t i = 0; i < BLOCK_SIZE_K - 1; ++i)
		output[i] = input[i + 1];
	output[BLOCK_SIZE_K - 1] = temp;
}

__device__ void xor_blockKG(BYTE* state, const BYTE* block, uint64_t size)
{
	for (uint64_t i = 0; i < size; ++i)
		state[i] ^= block[i];
}

// Write the ith assocated data block to "output".
// The nonce is prepended and padding is added as required.
// adlen is the length of the associated data in bytes
__device__ void get_ad_blockKG(BYTE* output, const BYTE* ad, uint64_t adlen, const BYTE* npub, uint64_t i)
{
	uint64_t len = 0;
	// First block contains nonce
	// Remark: nonce may not be longer then BLOCK_SIZE
	if (i == 0) {
		memcpy(output, npub, CRYPTO_NPUBBYTES);
		len += CRYPTO_NPUBBYTES;
	}

	const uint64_t block_offset = i * BLOCK_SIZE_K - (i != 0) * CRYPTO_NPUBBYTES;
	// If adlen is divisible by BLOCK_SIZE, add an additional padding block
	if (i != 0 && block_offset == adlen) {
		memset(output, 0x00, BLOCK_SIZE_K);
		output[0] = 0x01;
		return;
	}
	const uint64_t r_outlen = BLOCK_SIZE_K - len;
	const uint64_t r_adlen = adlen - block_offset;
	// Fill with associated data if available
	if (r_outlen <= r_adlen) { // enough AD
		memcpy(output + len, ad + block_offset, r_outlen);
	}
	else { // not enough AD, need to pad
		if (r_adlen > 0) // ad might be nullptr
			memcpy(output + len, ad + block_offset, r_adlen);
		memset(output + len + r_adlen, 0x00, r_outlen - r_adlen);
		output[len + r_adlen] = 0x01;
	}
}

// Return the ith ciphertext block.
// clen is the length of the ciphertext in bytes 
__device__ void get_c_blockKG(BYTE* output, const BYTE* c, uint64_t clen, uint64_t i)
{
	const uint64_t block_offset = i * BLOCK_SIZE_K;
	// If clen is divisible by BLOCK_SIZE, add an additional padding block
	if (block_offset == clen) {
		memset(output, 0x00, BLOCK_SIZE_K);
		output[0] = 0x01;
		return;
	}
	const uint64_t r_clen = clen - block_offset;
	// Fill with ciphertext if available
	if (BLOCK_SIZE_K <= r_clen) { // enough ciphertext
		memcpy(output, c + block_offset, BLOCK_SIZE_K);
	}
	else { // not enough ciphertext, need to pad
		if (r_clen > 0) // c might be nullptr
			memcpy(output, c + block_offset, r_clen);
		memset(output + r_clen, 0x00, BLOCK_SIZE_K - r_clen);
		output[r_clen] = 0x01;
	}
	__syncthreads();
}


/*******************************************************************************/
/*					        200 - Keccak Optimisation                          */
/*******************************************************************************/

__device__ __constant__ BYTE KeccakRoundConstantsG_Op[maxNrRounds] = {
	0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
	0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

__device__ const unsigned int KeccakRhoOffsetsG_Op[nrLanes] = {
	0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};

//__device__ void KeccakP200RoundG_Op(BYTE* state, unsigned int indexRound)
//{
//	//theta
//	unsigned int x, y;
//	BYTE C[5], D[5];
//
//	for (x = 0; x < 5; x++) {
//		C[x] = 0;
//		for (y = 0; y < 5; y++)
//			C[x] ^= state[index(x, y)];
//	}
//	for (x = 0; x < 5; x++)
//		D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
//	for (x = 0; x < 5; x++)
//		for (y = 0; y < 5; y++)
//			state[index(x, y)] ^= D[x];
//
//	//rho
//	for (x = 0; x < 5; x++)
//		for (y = 0; y < 5; y++)
//			state[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsetsG_Op[index(x, y)]);
//
//	//pi
//	BYTE tempA[25];
//
//	for (x = 0; x < 5; x++)
//		for (y = 0; y < 5; y++)
//			tempA[index(x, y)] = state[index(x, y)];
//	for (x = 0; x < 5; x++)
//		for (y = 0; y < 5; y++)
//			state[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];
//
//	//chi
//	BYTE E[5];
//
//	for (y = 0; y < 5; y++) {
//		for (x = 0; x < 5; x++)
//			E[x] = state[index(x, y)] ^ ((~state[index(x + 1, y)]) & state[index(x + 2, y)]);
//		for (x = 0; x < 5; x++)
//			state[index(x, y)] = E[x];
//	}
//
//	//iota
//	state[index(0, 0)] ^= KeccakRoundConstantsG_Op[indexRound];
//}

__device__ void permutationKG_Op(BYTE* state)
{
	unsigned int x, y;
	BYTE C[5], D[5];
	__shared__ BYTE tempA[25];

	for (unsigned int i = 0; i < maxNrRounds; i++) {

		//theta
		for (x = 0; x < 5; x++) {
			C[x] = 0;
			for (y = 0; y < 5; y++)
				C[x] ^= state[index(x, y)];
		}
		for (x = 0; x < 5; x++)
			D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				state[index(x, y)] ^= D[x];

		//rho
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				state[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsetsG_Op[index(x, y)]);

		//pi
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				tempA[index(x, y)] = state[index(x, y)];
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				state[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];

		//chi
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++)
				D[x] = state[index(x, y)] ^ ((~state[index(x + 1, y)]) & state[index(x + 2, y)]);
			for (x = 0; x < 5; x++)
				state[index(x, y)] = D[x];
		}

		//iota
		state[index(0, 0)] ^= KeccakRoundConstantsG_Op[i];
	}
	//KeccakP200RoundG_Op(state, i);
}

// State should be BLOCK_SIZE bytes long
// Note: input may be equal to output
__device__ void lfsr_stepKG_Op(BYTE* output, BYTE* input)
{
	BYTE temp = ((input[0] << 1) | (input[0] >> 7)) ^ ((input[2] << 1) | (input[2] >> 7)) ^ (input[13] << 1);

#pragma unroll
	for (uint64_t i = 0; i < BLOCK_SIZE_K - 1; ++i)
		output[i] = input[i + 1];
	output[BLOCK_SIZE_K - 1] = temp;
}

__device__ void xor_blockKG_Op(BYTE* state, const BYTE* block, uint64_t size)
{
	for (uint64_t i = 0; i < size; ++i)
		state[i] ^= block[i];
}

/*******************************************************************************/
/*					            200 - Keccak Fine                              */
/*******************************************************************************/

__device__ void lfsr_stepKG_Fine(BYTE* output, BYTE* input)
{
	BYTE temp = ((input[0] << 1) | (input[0] >> 7)) ^ ((input[2] << 1) | (input[2] >> 7)) ^ (input[13] << 1);

	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)(BLOCK_SIZE_K - 1) / (double)fineLevel)));
	int e = (c + ceil(((double)(BLOCK_SIZE_K - 1) / (double)fineLevel)));

#pragma unroll
	for (uint64_t i = c; i < e; ++i)
		output[i] = input[i + 1];
	__syncthreads();

	output[BLOCK_SIZE_K - 1] = temp;
}

__device__ void xor_blockKG_Fine(BYTE* state, const BYTE* block, uint64_t size)
{
	double innertid = (double)threadIdx.x / (double)fineLevel;
	int c = (innertid * fineLevel * ceil(((double)size / (double)fineLevel)));
	int e = (c + ceil(((double)size / (double)fineLevel)));

	for (uint64_t i = c; i < e; ++i)
		state[i] ^= block[i];

	__syncthreads();
}

__device__ void permutationKG_Fine(BYTE* state)
{
	unsigned int x, y;
	__shared__ BYTE C[5];
	__shared__ BYTE D[5];
	__shared__ BYTE tempA[25];

	for (unsigned int i = 0; i < maxNrRounds; i++) {

		double innertid = (double)threadIdx.x / (double)fineLevel;
		int c = (innertid * fineLevel * ceil(((double)5 / (double)fineLevel)));
		int e = (c + ceil(((double)5 / (double)fineLevel)));
		e = (e > 5) ? 5 : e; //prevent outofboudary

		//theta
		for (x = c; x < e; x++) {
			C[x] = 0;
			for (y = c; y < e; y++)
				C[x] ^= state[index(x, y)];
		}
		for (x = 0; x < 5; x++)
			D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];

		for (x = c; x < e; x++)
			for (y = c; y < e; y++)
				state[index(x, y)] ^= D[x];

		//rho
		for (x = c; x < e; x++)
			for (y = c; y < e; y++)
				state[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsetsG_Op[index(x, y)]);

		//pi
		for (x = c; x < e; x++)
			for (y = c; y < e; y++)
				tempA[index(x, y)] = state[index(x, y)];
		for (x = c; x < e; x++)
			for (y = c; y < e; y++)
				state[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];

		//chi
		for (y = c; y < e; y++) {
			for (x = c; x < e; x++)
				D[x] = state[index(x, y)] ^ ((~state[index(x + 1, y)]) & state[index(x + 2, y)]);
			for (x = c; x < e; x++)
				state[index(x, y)] = D[x];
		}

		//iota
		state[index(0, 0)] ^= KeccakRoundConstantsG_Op[i];
	}
}