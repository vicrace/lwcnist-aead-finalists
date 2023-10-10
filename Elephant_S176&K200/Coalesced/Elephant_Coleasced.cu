
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
	const unsigned char* k)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	const uint8_t * k) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	const unsigned char* k)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	const uint8_t * k) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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

///////////// Transpose
__global__ void crypto_aead_encrypt_gpu_global_S176_Trans(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
	(void)nsec;

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x * adlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * adlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + threadIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S);				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + (threadIdx.y * (blockDim.x * blockDim.x));

		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * adlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + tcix; // access in row  - cipher

		uint8_t* C = c + tc;
		uint8_t* M = const_cast<uint8_t*>(m) + tm;
		uint8_t* A = const_cast<uint8_t*>(ad) + ta;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tk;

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

__global__ void  crypto_aead_encrypt_gpu_global_K200_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x * adlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * adlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + threadIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K);				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + (threadIdx.y * (blockDim.x * blockDim.x));

		////copy row
		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * adlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + tcix; // access in row  - cipher

		uint8_t* C = c + tc;
		uint8_t* M = const_cast<uint8_t*>(m) + tm;
		uint8_t* A = const_cast<uint8_t*>(ad) + ta;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tk;

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

__global__ void crypto_aead_encrypt_gpu_global_S176_OpTrans(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
	(void)nsec;

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x * adlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * adlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + threadIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S);				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + (threadIdx.y * (blockDim.x * blockDim.x));

		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * adlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) + tcix; // access in row  - cipher

		uint8_t* C = c + tc;
		uint8_t* M = const_cast<uint8_t*>(m) + tm;
		uint8_t* A = const_cast<uint8_t*>(ad) + ta;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tk;

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

__global__ void  crypto_aead_encrypt_gpu_global_K200_OpTrans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x * adlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * adlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + threadIdx.x * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K);				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + (threadIdx.y * (blockDim.x * blockDim.x));

		////copy row
		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * adlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) + tcix; // access in row  - cipher

		uint8_t* C = c + tc;
		uint8_t* M = const_cast<uint8_t*>(m) + tm;
		uint8_t* A = const_cast<uint8_t*>(ad) + ta;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tk;

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
	const unsigned char* k)
{
	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	const uint8_t * k) {

	(void)nsec;

	int bid = blockIdx.x, tid = threadIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Elephant_CA_raw.csv", "w");
	fprintf(fpt, "Version, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	printf("Version\t\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");

	uint8_t* nonce, * key, * msg, * ad, * ct, * ct_K;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen, clen2;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_tS = 0, cpu_tK = 0;

	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ct, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
	cudaMallocHost((void**)& ct_K, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));

	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);

	//S176
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt_S176(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
		print('co', ct + (i * clen), clen);
#endif
	}
	QueryPerformanceCounter(&t2);
	cpu_tS += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host S176", 0.0, cpu_tS, 0.0, 0.0, cpu_tS, 0.0, BATCH / (cpu_tS / 1000), BATCH / (cpu_tS / 1000));
#endif
	printf("Host S176\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_tS, BATCH / (cpu_tS / 1000), BATCH / (cpu_tS / 1000));


	//K200
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt_K200(OFFSET(ct_K, i, clen2), &clen2, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}
	QueryPerformanceCounter(&t2);
	cpu_tK += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host K200", 0.0, cpu_tK, 0.0, 0.0, cpu_tK, 0.0, BATCH / (cpu_tK / 1000), BATCH / (cpu_tK / 1000));
#endif
	printf("Host K200\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_tK, BATCH / (cpu_tK / 1000), BATCH / (cpu_tK / 1000));

	//GPU implementation
	LARGE_INTEGER frequencyT;
	LARGE_INTEGER TS, TE;
	double trans = 0;
	uint8_t * key_out, *msg_out, *ad_out, *nonce_out;

	cudaMallocHost((void**)& key_out, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg_out, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad_out, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce_out, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));

	QueryPerformanceFrequency(&frequencyT);
	QueryPerformanceCounter(&TS);
	transposedata(key, key_out, BATCH, CRYPTO_KEYBYTES);
	transposedata(nonce, nonce_out, BATCH, CRYPTO_NPUBBYTES);
	transposedata(msg, msg_out, BATCH, mlen);
	transposedata(ad, ad_out, BATCH, alen);
	QueryPerformanceCounter(&TE);
	trans += (((double)(TE.QuadPart - TS.QuadPart) * 1000.0 / (double)frequencyT.QuadPart) / 100);


	uint8_t * d_n, *d_k, *d_a, *d_m, *d_cS, *h_cS, *d_cK, *h_cK;
	uint64_t * d_clen1, *d_clen2;
	cudaEvent_t start, stop;

	cudaEventCreate(&start);
	cudaEventCreate(&stop);

	//Memory Allocation - Device
	cudaMallocHost((void**)& h_cS, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));		//Host Cipher
	cudaMallocHost((void**)& h_cK, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));		//Host Cipher
	cudaMalloc((void**)& d_cS, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_cK, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_n, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
	cudaMalloc((void**)& d_k, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
	cudaMalloc((void**)& d_m, BATCH * (uint64_t)mlen * sizeof(uint8_t));				//Message
	cudaMalloc((void**)& d_a, BATCH * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
	cudaMallocHost((void**)& d_clen1, sizeof(uint64_t));
	cudaMallocHost((void**)& d_clen2, sizeof(uint64_t));

	//Memory initialisation
	cudaMemset(d_n, 0, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMemset(d_k, 0, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMemset(d_m, 0, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMemset(d_a, 0, BATCH * (uint64_t)alen * sizeof(uint8_t));
	memset(h_cS, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
	memset(h_cK, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));
	cudaMemset(d_cS, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
	cudaMemset(d_cK, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));


	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen1) * sizeof(uint8_t);

	for (int i = 64; i < 1025; i *= 2) {

		float memcpy_h2d, elapsed, memcpy_d2h, total;

		for (int z = 1; z < 9; z++) {

			if (z == 1) { // for non-coleasced
				cudaEventRecord(start, 0);
				CHECK(cudaMemcpy(d_n, nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_k, key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_m, msg, BATCH * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_a, ad, BATCH * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice));
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_h2d = 0.0f;
				cudaEventElapsedTime(&memcpy_h2d, start, stop);
			}
			else if (z == 5) { // for coleasced
				cudaEventRecord(start, 0);
				CHECK(cudaMemcpy(d_n, nonce_out, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_k, key_out, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_m, msg_out, BATCH * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice));
				CHECK(cudaMemcpy(d_a, ad_out, BATCH * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice));
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_h2d = 0.0f;
				cudaEventElapsedTime(&memcpy_h2d, start, stop);
			}


			dim3 threads(i);
			dim3 blocks(ceil((double)BATCH / (double)i));		//for unoptimised
			if (z > 4) {
				threads.y = i;
				double temp = (double)BATCH / ((double)threads.x * (double)threads.y);
				blocks.x = (temp < 1) ? 1 : ceil(temp); // at least 1 block
			}

			kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global_S176 : ((z == 2) ? &crypto_aead_encrypt_gpu_global_S176_MemOp
				: ((z == 3) ? &crypto_aead_encrypt_gpu_global_K200 : ((z == 4) ? &crypto_aead_encrypt_gpu_global_K200_MemOp :
				((z == 5) ? &crypto_aead_encrypt_gpu_global_S176_Trans : (z == 6) ? &crypto_aead_encrypt_gpu_global_K200_Trans :
					((z == 7) ? &crypto_aead_encrypt_gpu_global_S176_OpTrans : &crypto_aead_encrypt_gpu_global_K200_OpTrans))))));

			char* kernelName = ((z == 1) ? "S176 Ref   " : ((z == 2) ? "S176 Op   " : ((z == 3) ? "K200 Ref   " : ((z == 4) ? "K200 Op   " :
				((z == 5) ? "S176 Ref Trans" : (z == 6) ? "K200 Ref Trans" : ((z == 7) ? "S176 Op Trans" : "K200 Op Trans "))))));
			int len = ((z == 1 || z == 2 || z == 5 || z == 7) ? CRYPTO_ABYTES_S : CRYPTO_ABYTES_K);
			uint8_t * h_c = ((z == 1 || z == 2 || z == 5 || z == 7) ? h_cS : h_cK);
			uint8_t * d_c = ((z == 1 || z == 2 || z == 5 || z == 7) ? d_cS : d_cK);
			uint64_t * d_clen = ((z == 1 || z == 2 || z == 5 || z == 7) ? d_clen1 : d_clen2);

			//Kernel execution
			memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH(len) * sizeof(uint8_t));
			cudaEventRecord(start, 0);
			kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			elapsed = 0.0f;
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			if (z == 1 || z == 2 || z == 5 || z == 7)
				checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH(len));
			else
				checkResult(kernelName, ct_K, h_c, MAX_CIPHER_LENGTH(len));

			double Ttime = 0;
			if (z < 5)
				total = memcpy_h2d + elapsed + memcpy_d2h;
			else {
				total = memcpy_h2d + trans + elapsed + memcpy_d2h;
				Ttime = trans;
			}

			printf("%s\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t%.f\n", kernelName, threads.x, memcpy_h2d,
				memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));

#ifdef WRITEFILE
			fprintf(fpt, "%s, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, threads.x, total,
				memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif

		}
		printf("\n======================================================================================================================================================\n");

	}

	//Free Memory
	//Host memory
	cudaFree(nonce);
	cudaFree(key);
	cudaFree(msg);
	cudaFree(ad);
	cudaFree(ct);
	cudaFree(ct_K);

	//Device memory
	cudaFree(d_n);
	cudaFree(d_k);
	cudaFree(d_a);
	cudaFree(d_m);
	cudaFree(d_clen1);
	cudaFree(d_clen2);
	cudaFree(h_cS);
	cudaFree(h_cK);
	cudaFree(d_cS);
	cudaFree(d_cK);
	cudaEventDestroy(start);
	cudaEventDestroy(stop);

#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();
}