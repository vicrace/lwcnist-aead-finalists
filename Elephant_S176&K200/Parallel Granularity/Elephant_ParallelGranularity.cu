
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "params.h"
#include "elephantK.h"
#include "elephantS.h"
#include "operations.h"

int crypto_aead_encrypt_K200(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k) {

	(void)nsec;
	*clen = mlen + CRYPTO_ABYTES_K;
	BYTE tag[CRYPTO_ABYTES_K];
	int encrypt = 1;

	// Compute number of blocks
	const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_K;
	const uint64_t nblocks_m = (mlen % BLOCK_SIZE_K) ? nblocks_c : nblocks_c - 1;
	const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_K;
	const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

	// Storage for the expanded key L
	BYTE expanded_key[BLOCK_SIZE_K] = { 0 };
	memcpy(expanded_key, k, CRYPTO_KEYBYTES);
	permutationK(expanded_key);

	// Buffers for storing previous, current and next mask
	BYTE mask_buffer_1[BLOCK_SIZE_K] = { 0 };
	BYTE mask_buffer_2[BLOCK_SIZE_K] = { 0 };
	BYTE mask_buffer_3[BLOCK_SIZE_K] = { 0 };
	memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_K);

	BYTE * previous_mask = mask_buffer_1;
	BYTE * current_mask = mask_buffer_2;
	BYTE * next_mask = mask_buffer_3;

	// Buffer to store current ciphertext/AD block
	BYTE buffer[BLOCK_SIZE_K];

	// Tag buffer and initialization of tag to zero
	BYTE tag_buffer[BLOCK_SIZE_K] = { 0 };
	get_ad_blockK(tag_buffer, ad, adlen, npub, 0);

	uint64_t offset = 0;
	for (uint64_t i = 0; i < nb_it; ++i) {
		// Compute mask for the next message
		lfsr_stepK(next_mask, current_mask);

		if (i < nblocks_m) {
			// Compute ciphertext block
			memcpy(buffer, npub, CRYPTO_NPUBBYTES);
			memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_K - CRYPTO_NPUBBYTES);
			xor_blockK(buffer, current_mask, BLOCK_SIZE_K);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			permutationK(buffer);
			xor_blockK(buffer, current_mask, BLOCK_SIZE_K);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			const uint64_t r_LONG = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_K;
			xor_blockK(buffer, m + offset, r_LONG);
			memcpy(c + offset, buffer, r_LONG);
		}

		if (i > 0 && i <= nblocks_c) {
			// Compute tag for ciphertext block
			get_c_blockK(buffer, encrypt ? c : m, mlen, i - 1);
			xor_blockK(buffer, previous_mask, BLOCK_SIZE_K);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			permutationK(buffer);
			xor_blockK(buffer, previous_mask, BLOCK_SIZE_K);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			xor_blockK(tag_buffer, buffer, BLOCK_SIZE_K);
		}

		// If there is any AD left, compute tag for AD block 
		if (i + 1 < nblocks_ad) {
			get_ad_blockK(buffer, ad, adlen, npub, i + 1);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			permutationK(buffer);
			xor_blockK(buffer, next_mask, BLOCK_SIZE_K);
			xor_blockK(tag_buffer, buffer, BLOCK_SIZE_K);
		}

		// Cyclically shift the mask buffers 
		// Value of next_mask will be computed in the next iteration
		BYTE* const temp = previous_mask;
		previous_mask = current_mask;
		current_mask = next_mask;
		next_mask = temp;

		offset += BLOCK_SIZE_K;
	}
	// Compute tag
	xor_blockK(tag_buffer, expanded_key, BLOCK_SIZE_K);
	permutationK(tag_buffer);
	xor_blockK(tag_buffer, expanded_key, BLOCK_SIZE_K);
	memcpy(tag, tag_buffer, CRYPTO_ABYTES_K);

	memcpy(c + mlen, tag, CRYPTO_ABYTES_K);
	return 0;
}


int crypto_aead_encrypt_S176(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
	(void)nsec;
	*clen = mlen + CRYPTO_ABYTES_S;
	BYTE tag[CRYPTO_ABYTES_S];
	int encrypt = 1;

	// Compute number of blocks
	const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_S;
	const uint64_t nblocks_m = (mlen % BLOCK_SIZE_S) ? nblocks_c : nblocks_c - 1;
	const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_S;
	const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

	// Storage for the expanded key L
	BYTE expanded_key[BLOCK_SIZE_S] = { 0 };
	memcpy(expanded_key, k, CRYPTO_KEYBYTES);
	permutation(expanded_key);

	// Buffers for storing previous, current and next mask
	BYTE mask_buffer_1[BLOCK_SIZE_S] = { 0 };
	BYTE mask_buffer_2[BLOCK_SIZE_S] = { 0 };
	BYTE mask_buffer_3[BLOCK_SIZE_S] = { 0 };
	memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_S);

	BYTE * previous_mask = mask_buffer_1;
	BYTE * current_mask = mask_buffer_2;
	BYTE * next_mask = mask_buffer_3;

	// Buffer to store current ciphertext/AD block
	BYTE buffer[BLOCK_SIZE_S];

	// Tag buffer and initialization of tag to zero
	BYTE tag_buffer[BLOCK_SIZE_S] = { 0 };
	get_ad_block(tag_buffer, ad, adlen, npub, 0);

	uint64_t offset = 0;
	for (uint64_t i = 0; i < nb_it; ++i) {
		// Compute mask for the next message
		lfsr_step(next_mask, current_mask);

		if (i < nblocks_m) {
			// Compute ciphertext block
			memcpy(buffer, npub, CRYPTO_NPUBBYTES);
			memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_S - CRYPTO_NPUBBYTES);
			xor_block(buffer, current_mask, BLOCK_SIZE_S);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			permutation(buffer);
			xor_block(buffer, current_mask, BLOCK_SIZE_S);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			const uint64_t r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_S;
			xor_block(buffer, m + offset, r_size);
			memcpy(c + offset, buffer, r_size);
		}

		if (i > 0 && i <= nblocks_c) {
			// Compute tag for ciphertext block
			get_c_block(buffer, encrypt ? c : m, mlen, i - 1);
			xor_block(buffer, previous_mask, BLOCK_SIZE_S);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			permutation(buffer);
			xor_block(buffer, previous_mask, BLOCK_SIZE_S);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			xor_block(tag_buffer, buffer, BLOCK_SIZE_S);
		}

		// If there is any AD left, compute tag for AD block 
		if (i + 1 < nblocks_ad) {
			get_ad_block(buffer, ad, adlen, npub, i + 1);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			permutation(buffer);
			xor_block(buffer, next_mask, BLOCK_SIZE_S);
			xor_block(tag_buffer, buffer, BLOCK_SIZE_S);
		}

		// Cyclically shift the mask buffers 
		// Value of next_mask will be computed in the next iteration
		BYTE* const temp = previous_mask;
		previous_mask = current_mask;
		current_mask = next_mask;
		next_mask = temp;

		offset += BLOCK_SIZE_S;
	}
	// Compute tag
	xor_block(tag_buffer, expanded_key, BLOCK_SIZE_S);
	permutation(tag_buffer);
	xor_block(tag_buffer, expanded_key, BLOCK_SIZE_S);
	memcpy(tag, tag_buffer, CRYPTO_ABYTES_S);

	memcpy(c + mlen, tag, CRYPTO_ABYTES_S);
	return 0;
}


__global__ void crypto_aead_encrypt_gpu_global_S176(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k,
	int Batch)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + tid * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_S;
		BYTE tag[CRYPTO_ABYTES_S];
		int encrypt = 1;

		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_S;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_S) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_S;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		BYTE expanded_key[BLOCK_SIZE_S] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationG(expanded_key);

		BYTE mask_buffer_1[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_S] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_S);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		BYTE buffer[BLOCK_SIZE_S];

		BYTE tag_buffer[BLOCK_SIZE_S] = { 0 };
		get_ad_blockG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			lfsr_stepG(next_mask, current_mask);

			if (i < nblocks_m) {
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_S - CRYPTO_NPUBBYTES);
				xor_blockG(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				permutationG(buffer);
				xor_blockG(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				const uint64_t r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_S;
				xor_blockG(buffer, M + offset, r_size);
				memcpy(C + offset, buffer, r_size);
			}

			if (i > 0 && i <= nblocks_c) {
				get_c_blockG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockG(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				permutationG(buffer);
				xor_blockG(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			if (i + 1 < nblocks_ad) {
				get_ad_blockG(buffer, A, adlen, N, i + 1);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				permutationG(buffer);
				xor_blockG(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_S;
		}

		xor_blockG(tag_buffer, expanded_key, BLOCK_SIZE_S);
		permutationG(tag_buffer);
		xor_blockG(tag_buffer, expanded_key, BLOCK_SIZE_S);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_S);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_S);
	}
}

__global__ void  crypto_aead_encrypt_gpu_global_K200(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + tid * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_K;
		BYTE tag[CRYPTO_ABYTES_K];
		int encrypt = 1;

		// Compute number of blocks
		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_K;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_K) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_K;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		// Storage for the expanded key L
		BYTE expanded_key[BLOCK_SIZE_K] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationKG(expanded_key);

		// Buffers for storing previous, current and next mask
		BYTE mask_buffer_1[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_K] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_K);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		// Buffer to store current ciphertext/AD block
		BYTE buffer[BLOCK_SIZE_K];

		// Tag buffer and initialization of tag to zero
		BYTE tag_buffer[BLOCK_SIZE_K] = { 0 };
		get_ad_blockKG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			// Compute mask for the next message
			lfsr_stepKG(next_mask, current_mask);

			if (i < nblocks_m) {
				// Compute ciphertext block
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_K - CRYPTO_NPUBBYTES);
				xor_blockKG(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG(buffer);
				xor_blockKG(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				const uint64_t r_LONG = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_K;
				xor_blockKG(buffer, M + offset, r_LONG);
				memcpy(C + offset, buffer, r_LONG);
			}

			if (i > 0 && i <= nblocks_c) {
				// Compute tag for ciphertext block
				get_c_blockKG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockKG(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG(buffer);
				xor_blockKG(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// If there is any AD left, compute tag for AD block 
			if (i + 1 < nblocks_ad) {
				get_ad_blockKG(buffer, A, adlen, N, i + 1);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG(buffer);
				xor_blockKG(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// Cyclically shift the mask buffers 
			// Value of next_mask will be computed in the next iteration
			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_K;
		}
		// Compute tag
		xor_blockKG(tag_buffer, expanded_key, BLOCK_SIZE_K);
		permutationKG(tag_buffer);
		xor_blockKG(tag_buffer, expanded_key, BLOCK_SIZE_K);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_K);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_K);
	}
}

__global__ void crypto_aead_encrypt_gpu_global_S176_MemOp(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k,
	int Batch)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + tid * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_S;
		BYTE tag[CRYPTO_ABYTES_S];
		int encrypt = 1;

		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_S;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_S) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_S;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		BYTE expanded_key[BLOCK_SIZE_S] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationG_Op(expanded_key);

		BYTE mask_buffer_1[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_S] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_S);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		BYTE buffer[BLOCK_SIZE_S];

		BYTE tag_buffer[BLOCK_SIZE_S] = { 0 };
		get_ad_blockG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			lfsr_stepG_Op(next_mask, current_mask);

			if (i < nblocks_m) {
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_S - CRYPTO_NPUBBYTES);
				xor_blockG_Unroll(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Op(buffer);
				xor_blockG_Unroll(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				const uint64_t r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_S;
				xor_blockG_Unroll(buffer, M + offset, r_size);
				memcpy(C + offset, buffer, r_size);
			}

			if (i > 0 && i <= nblocks_c) {
				get_c_blockG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockG_Unroll(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Op(buffer);
				xor_blockG_Unroll(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			if (i + 1 < nblocks_ad) {
				get_ad_blockG(buffer, A, adlen, N, i + 1);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Op(buffer);
				xor_blockG_Unroll(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG_Unroll(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_S;
		}

		xor_blockG_Unroll(tag_buffer, expanded_key, BLOCK_SIZE_S);
		permutationG_Op(tag_buffer);
		xor_blockG_Unroll(tag_buffer, expanded_key, BLOCK_SIZE_S);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_S);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_S);
	}
}

__global__ void  crypto_aead_encrypt_gpu_global_K200_MemOp(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + tid * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_K;
		BYTE tag[CRYPTO_ABYTES_K];
		int encrypt = 1;

		// Compute number of blocks
		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_K;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_K) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_K;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		// Storage for the expanded key L
		BYTE expanded_key[BLOCK_SIZE_K] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationKG_Op(expanded_key);

		// Buffers for storing previous, current and next mask
		BYTE mask_buffer_1[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_K] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_K);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		// Buffer to store current ciphertext/AD block
		BYTE buffer[BLOCK_SIZE_K];

		// Tag buffer and initialization of tag to zero
		BYTE tag_buffer[BLOCK_SIZE_K] = { 0 };
		get_ad_blockKG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			// Compute mask for the next message
			lfsr_stepKG_Op(next_mask, current_mask);

			if (i < nblocks_m) {
				// Compute ciphertext block
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_K - CRYPTO_NPUBBYTES);
				xor_blockKG_Op(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Op(buffer);
				xor_blockKG_Op(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				const uint64_t r_LONG = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_K;
				xor_blockKG_Op(buffer, M + offset, r_LONG);
				memcpy(C + offset, buffer, r_LONG);
			}

			if (i > 0 && i <= nblocks_c) {
				// Compute tag for ciphertext block
				get_c_blockKG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockKG_Op(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Op(buffer);
				xor_blockKG_Op(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// If there is any AD left, compute tag for AD block 
			if (i + 1 < nblocks_ad) {
				get_ad_blockKG(buffer, A, adlen, N, i + 1);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Op(buffer);
				xor_blockKG_Op(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG_Op(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// Cyclically shift the mask buffers 
			// Value of next_mask will be computed in the next iteration
			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_K;
		}
		// Compute tag
		xor_blockKG_Op(tag_buffer, expanded_key, BLOCK_SIZE_K);
		permutationKG_Op(tag_buffer);
		xor_blockKG_Op(tag_buffer, expanded_key, BLOCK_SIZE_K);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_K);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_K);
	}
}

__global__ void crypto_aead_encrypt_gpu_global_S176_FineOp(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k,
	int Batch)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + ((tid / fineLevel) * adlen);			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES); //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + ((tid / fineLevel) * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S));	//instead of crypto_abytes

		uint8_t * C = c + offset_ct;
		uint8_t * M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t * A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t * N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t * K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_S;
		BYTE tag[CRYPTO_ABYTES_S];
		int encrypt = 1;

		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_S;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_S) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_S;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		BYTE expanded_key[BLOCK_SIZE_S] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationG_Fine(expanded_key);

		BYTE mask_buffer_1[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_S] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_S] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_S);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		BYTE buffer[BLOCK_SIZE_S];

		BYTE tag_buffer[BLOCK_SIZE_S] = { 0 };
		get_ad_blockG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			lfsr_stepG_Fine(next_mask, current_mask);

			if (i < nblocks_m) {
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_S - CRYPTO_NPUBBYTES);
				xor_blockG_FineOp(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Fine(buffer);
				xor_blockG_FineOp(buffer, current_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				const uint64_t r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_S;
				xor_blockG_FineOp(buffer, M + offset, r_size);
				memcpy(C + offset, buffer, r_size);
			}

			if (i > 0 && i <= nblocks_c) {
				get_c_blockG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockG_FineOp(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Fine(buffer);
				xor_blockG_FineOp(buffer, previous_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			if (i + 1 < nblocks_ad) {
				get_ad_blockG(buffer, A, adlen, N, i + 1);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				permutationG_Fine(buffer);
				xor_blockG_FineOp(buffer, next_mask, BLOCK_SIZE_S);
				xor_blockG_FineOp(tag_buffer, buffer, BLOCK_SIZE_S);
			}

			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_S;
		}

		xor_blockG_FineOp(tag_buffer, expanded_key, BLOCK_SIZE_S);
		permutationG_Fine(tag_buffer);
		xor_blockG_FineOp(tag_buffer, expanded_key, BLOCK_SIZE_S);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_S);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_S);
	}
}

__global__ void  crypto_aead_encrypt_gpu_global_K200_FineOp(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + ((tid / fineLevel) * adlen);			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES); //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + ((tid / fineLevel) * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S));	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		*clen = mlen + CRYPTO_ABYTES_K;
		BYTE tag[CRYPTO_ABYTES_K];
		int encrypt = 1;

		// Compute number of blocks
		const uint64_t nblocks_c = 1 + mlen / BLOCK_SIZE_K;
		const uint64_t nblocks_m = (mlen % BLOCK_SIZE_K) ? nblocks_c : nblocks_c - 1;
		const uint64_t nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE_K;
		const uint64_t nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

		// Storage for the expanded key L
		BYTE expanded_key[BLOCK_SIZE_K] = { 0 };
		memcpy(expanded_key, K, CRYPTO_KEYBYTES);
		permutationKG_Fine(expanded_key);

		// Buffers for storing previous, current and next mask
		BYTE mask_buffer_1[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_2[BLOCK_SIZE_K] = { 0 };
		BYTE mask_buffer_3[BLOCK_SIZE_K] = { 0 };
		memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE_K);

		BYTE * previous_mask = mask_buffer_1;
		BYTE * current_mask = mask_buffer_2;
		BYTE * next_mask = mask_buffer_3;

		// Buffer to store current ciphertext/AD block
		BYTE buffer[BLOCK_SIZE_K];

		// Tag buffer and initialization of tag to zero
		BYTE tag_buffer[BLOCK_SIZE_K] = { 0 };
		get_ad_blockKG(tag_buffer, A, adlen, N, 0);

		uint64_t offset = 0;
		for (uint64_t i = 0; i < nb_it; ++i) {
			// Compute mask for the next message
			lfsr_stepKG_Fine(next_mask, current_mask);

			if (i < nblocks_m) {
				// Compute ciphertext block
				memcpy(buffer, N, CRYPTO_NPUBBYTES);
				memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE_K - CRYPTO_NPUBBYTES);
				xor_blockKG_Fine(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Fine(buffer);
				xor_blockKG_Fine(buffer, current_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				const uint64_t r_LONG = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE_K;
				xor_blockKG_Fine(buffer, M + offset, r_LONG);
				memcpy(C + offset, buffer, r_LONG);
			}

			if (i > 0 && i <= nblocks_c) {
				// Compute tag for ciphertext block
				get_c_blockKG(buffer, encrypt ? C : M, mlen, i - 1);
				xor_blockKG_Fine(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Fine(buffer);
				xor_blockKG_Fine(buffer, previous_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// If there is any AD left, compute tag for AD block 
			if (i + 1 < nblocks_ad) {
				get_ad_blockKG(buffer, A, adlen, N, i + 1);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				permutationKG_Fine(buffer);
				xor_blockKG_Fine(buffer, next_mask, BLOCK_SIZE_K);
				xor_blockKG_Fine(tag_buffer, buffer, BLOCK_SIZE_K);
			}

			// Cyclically shift the mask buffers 
			// Value of next_mask will be computed in the next iteration
			BYTE* const temp = previous_mask;
			previous_mask = current_mask;
			current_mask = next_mask;
			next_mask = temp;

			offset += BLOCK_SIZE_K;
		}
		// Compute tag
		xor_blockKG_Fine(tag_buffer, expanded_key, BLOCK_SIZE_K);
		permutationKG_Fine(tag_buffer);
		xor_blockKG_Fine(tag_buffer, expanded_key, BLOCK_SIZE_K);
		memcpy(tag, tag_buffer, CRYPTO_ABYTES_K);

		memcpy(C + mlen, tag, CRYPTO_ABYTES_K);
	}
}

int main()
{
	FILE* fpt;

#ifdef WRITEFILE
	char writeFile[100];
	char fineLvl[1];
	strcpy(writeFile, "Elephant_PGResult_F");
	sprintf(fineLvl, "%d", fineLevel);
	strcat(writeFile, fineLvl);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ct, * ct_Op;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen, clen2;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_tS = 0, cpu_tK = 0;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
		cudaMallocHost((void**)& ct_Op, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		/* <summary>
		 Spongent 176
		 </summary>
		 <returns></returns>*/
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {
#ifdef PRINT
			print('k', key + (i * CRYPTO_KEYBYTES), CRYPTO_KEYBYTES);
			printf(" ");
			print('n', nonce + (i * CRYPTO_NPUBBYTES), CRYPTO_NPUBBYTES);
			print('a', ad + (i * alen), alen);
			printf(" ");
			print('m', msg + (i * mlen), mlen);
			printf(" -> ");
#endif

			int result = crypto_aead_encrypt_S176(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
			print('cr', ct + (i * clen), clen);
#endif
		}
		QueryPerformanceCounter(&t2);
		cpu_tS = 0;
		cpu_tS += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		printf("\nVersion \t\tLatency (ms)\t\t\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-S176", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t)) * 1e-6) / cpu_tS, cpu_tS, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tS) * 8, 0.0, cpu_tS, 0.0, BATCH[z] / (cpu_tS / 1000), 0.0);
#endif
		printf("\nHost S176 Time :\t %.6f ms\t\t\t\t\t\t%.f\n", cpu_tS, BATCH[z] / (cpu_tS / 1000));

		/// <summary>
		/// Keccak 200
		/// </summary>
		/// <returns></returns>
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {

			int result = crypto_aead_encrypt_K200(OFFSET(ct_Op, i, clen2), &clen2, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
			print('co', ct_Op + (i * clen2), clen2);
#endif
		}
		QueryPerformanceCounter(&t2);
		cpu_tK = 0;
		cpu_tK += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		//Print Host Time - Op
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-K200", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t)) * 1e-6) / cpu_tK, cpu_tK, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tK) * 8, 0.0, cpu_tK, 0.0, BATCH[z] / (cpu_tK / 1000), 0.0);
#endif
		printf("Host K200 Time :\t %.6f ms\t\t\t\t\t\t%.f\n", cpu_tK, BATCH[z] / (cpu_tK / 1000));


		//GPU implementation
		uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c, *d_ck, *h_ck;
		uint64_t * d_clen, *d_clen2;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)& h_c, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));		//Host Cipher
		cudaMallocHost((void**)& h_ck, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));		//Host Cipher
		cudaMalloc((void**)& d_c, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_ck, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_n, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
		cudaMalloc((void**)& d_k, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
		cudaMalloc((void**)& d_m, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));				//Message
		cudaMalloc((void**)& d_a, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
		cudaMallocHost((void**)& d_clen, sizeof(uint64_t));
		cudaMallocHost((void**)& d_clen2, sizeof(uint64_t));

		//Memory initialisation
		memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
		memset(h_ck, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));
		cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
		cudaMemset(d_ck, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));
		cudaMemset(d_n, 0, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMemset(d_k, 0, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMemset(d_m, 0, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));
		cudaMemset(d_a, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));

		//Memory Copy from H2D
		cudaEventRecord(start, 0);
		cudaMemcpy(d_n, nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_k, key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_m, msg, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_a, ad, BATCH[z] * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float memcyp_h2d;
		cudaEventElapsedTime(&memcyp_h2d, start, stop);
		printf("\nMemcpy H2D :\t %.6f ms\t(%f GB/s)\n\n", memcyp_h2d, ((BATCH[z] * mlen * sizeof(uint8_t)) * 1e-6) / memcyp_h2d);

		for (int i = 1; i < 1025; i *= 2) {
			int blocks = ((BATCH[z] / i) < 1) ? 1 : ceil((double)BATCH[z] / (double)i);

			//S176
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_S176 << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_d2h, kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU S176 Ref", ct, h_c, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S), BATCH[z]);
#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tS, fpt, BATCH[z], "GPU S176", CRYPTO_ABYTES_S);
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tS, NULL, BATCH[z], "GPU S176", CRYPTO_ABYTES_S);
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));



			//S176 - Memory optimisation
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_S176_MemOp << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU S176 Op", ct, h_c, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S), BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tS, fpt, BATCH[z], "GPU S176 MemOp", CRYPTO_ABYTES_S);
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tS, NULL, BATCH[z], "GPU S176 MemOp", CRYPTO_ABYTES_S);
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));



			//K200
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_K200 << <blocks, i >> > (d_ck, d_clen2, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_ck, d_ck, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU K200", ct_Op, h_ck, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K), BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct_Op, h_ck, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tK, fpt, BATCH[z], "GPU K200", CRYPTO_ABYTES_K);
#else
			PrintTime(ct_Op, h_ck, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tK, NULL, BATCH[z], "GPU K200", CRYPTO_ABYTES_K);
#endif
			memset(h_ck, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));


			//K200 - Memory Optimisation
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_K200_MemOp << <blocks, i >> > (d_ck, d_clen2, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_ck, d_ck, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU K200 Op", ct_Op, h_ck, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K), BATCH[z]);
#ifdef WRITEFILE
			PrintTime(ct_Op, h_ck, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tK, fpt, BATCH[z], "GPU K200 MemOp", CRYPTO_ABYTES_K);
#else
			PrintTime(ct_Op, h_ck, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tK, NULL, BATCH[z], "GPU K200 MemOp", CRYPTO_ABYTES_K);
#endif
			memset(h_ck, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));


			//For fine grain
			if (i == fineLevel) {
				size_t size = BATCH[z] * (*d_clen) * sizeof(uint8_t);
				dim3 threads(Tlimit); //fine grain each block max 512 threads to divide by 4/8/16 threads for fine grain.
				double temp = ((double)BATCH[z] / (Tlimit / (double)fineLevel));
				dim3 blocks2(ceil(temp));		//for unoptimised


				//S176 fine grain - spongent
				cudaEventRecord(start, 0);
				crypto_aead_encrypt_gpu_global_S176_FineOp << <blocks2, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				float elapsed = 0;
				cudaEventElapsedTime(&elapsed, start, stop);

				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_d2h = 0;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult("GPU S176 Fine", ct, h_c, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S), BATCH[z]);
				memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));

				float total = memcyp_h2d + elapsed + memcpy_d2h;
				printf("KernelT%d :\t\t %.6f ms\t %.2f times\t%.f \t %s%d\n", i, total, (cpu_tS / total), BATCH[z] / (total / 1000), "S176 Fine ", fineLevel);
#ifdef WRITEFILE
				fprintf(fpt, "T%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f, %s%d\n", i, BATCH[z], (size* 2e-6) / total, total, (cpu_tS / total), ((size* 2e-6) / total) * 8, memcyp_h2d, elapsed, (cpu_tS / elapsed), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_tS / 1000)), "S176 Fine", fineLevel);
#endif

				//K200 fine grain - keccack
				cudaEventRecord(start, 0);
				crypto_aead_encrypt_gpu_global_K200_FineOp << <blocks2, threads >> > (d_ck, d_clen2, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				elapsed = 0;
				cudaEventElapsedTime(&elapsed, start, stop);

				cudaEventRecord(start, 0);
				cudaMemcpy(h_ck, d_ck, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_d2h = 0;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult("GPU K200 Fine", ct_Op, h_ck, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K), BATCH[z]);
				memset(h_ck, 0, BATCH[z] * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));

				total = memcyp_h2d + elapsed + memcpy_d2h;
				printf("KernelT%d :\t\t %.6f ms\t %.2f times\t%.f \t %s%d\n", i, total, (cpu_tK / total), BATCH[z] / (total / 1000), "K200 Fine ", fineLevel);
#ifdef WRITEFILE
				fprintf(fpt, "T%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f, %s%d\n", i, BATCH[z], (size* 2e-6) / total, total, (cpu_tK / total), ((size* 2e-6) / total) * 8, memcyp_h2d, elapsed, (cpu_tK / elapsed), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_tK / 1000)), "K200 Fine ", fineLevel);
#endif
			}
		}
		//Free Memory
		//Host memory
		cudaFree(nonce);
		cudaFree(key);
		cudaFree(msg);
		cudaFree(ad);
		cudaFree(ct);
		cudaFree(ct_Op);

		//Device memory
		cudaFree(d_n);
		cudaFree(d_k);
		cudaFree(d_a);
		cudaFree(d_m);
		cudaFree(d_c);
		cudaFree(h_c);
		cudaFree(h_ck);
		cudaFree(d_clen);
		cudaFree(d_clen2);

		cudaEventDestroy(start);
		cudaEventDestroy(stop);
		printf("-----------------------------------------------------------------------------------------------------\n");
	}

#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();
	return 0;
}