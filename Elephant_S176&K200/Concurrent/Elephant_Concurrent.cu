
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
	char writeFile[100];
	char fineLvl[1];
	strcpy(writeFile, "Elephant_Concurent_raw_F");
	sprintf(fineLvl, "%d", fineLevel);
	strcat(writeFile, fineLvl);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Dimension, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	printf("\nSize Implementation : %d\n", BATCH);

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
		print('c', ct + (i * clen), clen);
#endif
	}
	QueryPerformanceCounter(&t2);
	cpu_tS += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	//Print Time
	printf("Version\tCKernel\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host S176", 0, 0.0, cpu_tS, 0.0, 0.0, cpu_tS, 0.0, BATCH / (cpu_tS / 1000), BATCH / (cpu_tS / 1000));
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
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host K200", 0, 0.0, cpu_tK, 0.0, 0.0, cpu_tK, 0.0, BATCH / (cpu_tK / 1000), BATCH / (cpu_tK / 1000));
#endif
	printf("Host K200\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0,cpu_tK, BATCH / (cpu_tK / 1000), BATCH / (cpu_tK / 1000));


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

	//Memory Copy from H2D
	cudaEventRecord(start, 0);
	cudaMemcpy(d_n, nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_k, key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_m, msg, BATCH * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_a, ad, BATCH * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaEventRecord(stop, 0);
	cudaEventSynchronize(stop);
	float memcpy_h2d;
	cudaEventElapsedTime(&memcpy_h2d, start, stop);

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen1) * sizeof(uint8_t);

	cudaStream_t GPUs2[2], GPUs4[4], GPUs5[5];
	cudaStream_t * GPUstreams;


	for (int z = 2; z <= NSTREAM_SIZE; z++) {
		if (z != 3) {
			switch (z) {
			case 2: {GPUstreams = GPUs2; break; }
			case 4: {GPUstreams = GPUs4; break; }
			case 5: {GPUstreams = GPUs5; break; }
			}

			for (int a = 0; a < z; a++) {	//1 streams 8 bits
				CHECK(cudaStreamCreate(&GPUstreams[a]));
			}

			//Determine data size
			int iBATCH = BATCH / z;
			size_t iKeysize = iBATCH * CRYPTO_KEYBYTES * sizeof(uint8_t);
			size_t iNoncesize = iBATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t);
			size_t iMsgsize = iBATCH * (uint64_t)mlen * sizeof(uint8_t);
			size_t iAdsize = iBATCH * (uint64_t)alen * sizeof(uint8_t);

			for (int i = 64; i < 1025; i *= 2) {

				float elapsed, memcpy_d2h, total;

				//1 for S176 1D, 2 for K200 1D, 3 for S176 Trans, 4 for K200 Trans
				for (int a = 1; a <= 8; a++) {
					if (a == 1) {
						cudaEventRecord(start, 0);
						for (int i = 0; i < z; ++i)
						{
							int ioffset = i * iBATCH;
							cudaMemcpyAsync(&d_n[ioffset * CRYPTO_NPUBBYTES], &nonce[ioffset * CRYPTO_NPUBBYTES], iNoncesize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_k[ioffset * CRYPTO_KEYBYTES], &key[ioffset * CRYPTO_KEYBYTES], iKeysize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_m[ioffset * mlen], &msg[ioffset * mlen], iMsgsize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_a[ioffset * alen], &ad[ioffset * alen], iAdsize, cudaMemcpyHostToDevice, GPUstreams[i]);
						}
						cudaEventRecord(stop, 0);
						cudaEventSynchronize(stop);
						memcpy_h2d = 0.0f;
						cudaEventElapsedTime(&memcpy_h2d, start, stop);
					}
					else if (a == 5) {
						cudaEventRecord(start, 0);
						for (int i = 0; i < z; ++i)
						{
							int ioffset = i * iBATCH;
							cudaMemcpyAsync(&d_n[ioffset * CRYPTO_NPUBBYTES], &nonce_out[ioffset * CRYPTO_NPUBBYTES], iNoncesize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_k[ioffset * CRYPTO_KEYBYTES], &key_out[ioffset * CRYPTO_KEYBYTES], iKeysize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_m[ioffset * mlen], &msg_out[ioffset * mlen], iMsgsize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_a[ioffset * alen], &ad_out[ioffset * alen], iAdsize, cudaMemcpyHostToDevice, GPUstreams[i]);
						}
						cudaEventRecord(stop, 0);
						cudaEventSynchronize(stop);
						memcpy_h2d = 0.0f;
						cudaEventElapsedTime(&memcpy_h2d, start, stop);
					}

					//Configuration.
					dim3 threads(i);
					double temp = (double)iBATCH / (double)i;
					dim3 blocks(ceil(temp));		//for unoptimised

					if (a > 4) {
						threads.y = i;
						temp = (double)iBATCH / ((double)threads.x * (double)threads.y);
						blocks.x = ceil(temp);
						blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
					}

					kernel = ((a == 1) ? &crypto_aead_encrypt_gpu_global_S176 : ((a == 2) ? &crypto_aead_encrypt_gpu_global_S176_MemOp
						: ((a == 3) ? &crypto_aead_encrypt_gpu_global_K200 : ((a == 4) ? &crypto_aead_encrypt_gpu_global_K200_MemOp :
						((a == 5) ? &crypto_aead_encrypt_gpu_global_S176_Trans : (a == 6) ? &crypto_aead_encrypt_gpu_global_K200_Trans :
							((a == 7) ? &crypto_aead_encrypt_gpu_global_S176_OpTrans : &crypto_aead_encrypt_gpu_global_K200_OpTrans))))));

					char* kernelName = ((a == 1) ? "S176 Ref   " : ((a == 2) ? "S176 Op   " : ((a == 3) ? "K200 Ref   " : ((a == 4) ? "K200 Op   " :
						((a == 5) ? "S176 Ref Trans" : (a == 6) ? "K200 Ref Trans" : ((a == 7) ? "S176 Op Trans" : "K200 Op Trans "))))));

					//Memory allocation
					int len = ((a == 1 || a == 2 || a == 5 || a == 7) ? CRYPTO_ABYTES_S : CRYPTO_ABYTES_K);
					size_t iCsize = iBATCH * MAX_CIPHER_LENGTH(len) * sizeof(uint8_t);
					uint8_t * h_c = ((a == 1 || a == 2 || a == 5 || a == 7) ? h_cS : h_cK);
					uint8_t * d_c = ((a == 1 || a == 2 || a == 5 || a == 7) ? d_cS : d_cK);
					uint64_t * d_clen = ((a == 1 || a == 2 || a == 5 || a == 7) ? d_clen1 : d_clen2);

					memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH(len) * sizeof(uint8_t));
					cudaEventRecord(start);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						kernel << <blocks, threads, 0, GPUstreams[i] >> > (&d_c[ioffset * MAX_CIPHER_LENGTH(len)], d_clen, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
							&d_n[ioffset * CRYPTO_NPUBBYTES], &d_k[ioffset * CRYPTO_KEYBYTES]);
					}
					cudaEventRecord(stop);
					cudaEventSynchronize(stop);
					elapsed = 0.0f;
					cudaEventElapsedTime(&elapsed, start, stop);

					//Memory Copy from D2H
					cudaEventRecord(start, 0);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						cudaMemcpyAsync(&h_c[ioffset * MAX_CIPHER_LENGTH(len)], &d_c[ioffset * MAX_CIPHER_LENGTH(len)], iCsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
					}
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					memcpy_d2h = 0.0f;
					cudaEventElapsedTime(&memcpy_d2h, start, stop);

					if (a == 1 || a == 2 || a == 5 || a == 7)
						checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH(len));
					else
						checkResult(kernelName, ct_K, h_c, MAX_CIPHER_LENGTH(len));

					double Ttime = 0;
					if (a < 3)
						total = memcpy_h2d + elapsed + memcpy_d2h;
					else {
						total = memcpy_h2d + trans + elapsed + memcpy_d2h;
						Ttime = trans;
					}

					printf("%s\t %d\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t%.f\n", kernelName, z, threads.x, memcpy_h2d,
						memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#ifdef WRITEFILE
					fprintf(fpt, "%s,%d, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, z, threads.x, total,
						memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif
				}

				printf("\n");
			}


			//Fine Grain
			size_t size = BATCH * (clen) * sizeof(uint8_t);
			dim3 threads2(Tlimit); //fine grain each block max 512 threads to divide by 4/8/16 threads for fine grain.
			double temp = ((double)BATCH / (Tlimit / (double)fineLevel));
			dim3 blocks2(ceil(temp));


			cudaEventRecord(start, 0);
			for (int i = 0; i < z; ++i)
			{
				int ioffset = i * iBATCH;
				cudaMemcpyAsync(&d_n[ioffset * CRYPTO_NPUBBYTES], &nonce[ioffset * CRYPTO_NPUBBYTES], iNoncesize, cudaMemcpyHostToDevice, GPUstreams[i]);
				cudaMemcpyAsync(&d_k[ioffset * CRYPTO_KEYBYTES], &key[ioffset * CRYPTO_KEYBYTES], iKeysize, cudaMemcpyHostToDevice, GPUstreams[i]);
				cudaMemcpyAsync(&d_m[ioffset * mlen], &msg[ioffset * mlen], iMsgsize, cudaMemcpyHostToDevice, GPUstreams[i]);
				cudaMemcpyAsync(&d_a[ioffset * alen], &ad[ioffset * alen], iAdsize, cudaMemcpyHostToDevice, GPUstreams[i]);
			}
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_h2d = 0.0f;
			cudaEventElapsedTime(&memcpy_h2d, start, stop);

			//S176 fine grain - spongent
			size_t iSsize = iBATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t);

			memset(h_cS, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S) * sizeof(uint8_t));
			cudaEventRecord(start);
			for (int i = 0; i < z; ++i) {
				int ioffset = i * iBATCH;
				crypto_aead_encrypt_gpu_global_S176_FineOp << <blocks2, threads2, 0, GPUstreams[i] >> > (&d_cS[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S)], d_clen1, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
					&d_n[ioffset * CRYPTO_NPUBBYTES], &d_k[ioffset * CRYPTO_KEYBYTES]);
			}
			cudaEventRecord(stop);
			cudaEventSynchronize(stop);
			float elapsed = 0.0f;
			cudaEventElapsedTime(&elapsed, start, stop);

			cudaEventRecord(start, 0);
			for (int i = 0; i < z; ++i) {
				int ioffset = i * iBATCH;
				cudaMemcpyAsync(&h_cS[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S)], &d_cS[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S)], iSsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
			}
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("S176 Fine", ct, h_cS, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_S));
			float total = memcpy_h2d + elapsed + memcpy_d2h;

			printf("%s%d\t%d\t\t%.6f\t%.6f\t%.6f \t%.f\n", "S176 Fine ", fineLevel, z, memcpy_h2d,
				memcpy_d2h, total, BATCH / (total / 1000));

#ifdef WRITEFILE
			fprintf(fpt, "%s%d, %d, (%u)(%u %u), %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.f,%.2f\n", "S176 Fine ", fineLevel, z, blocks2.x, threads2.x, threads2.y, (size * 2e-6) / total, total,
				cpu_tS / total, (size * 2e-6) / total * 8, memcpy_h2d, elapsed, memcpy_d2h, cpu_tS / elapsed, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_tS / 1000)));
#endif

			//K200 fine grain - keccak
			size_t iKsize = iBATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t);

			memset(h_cK, 0, BATCH * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K) * sizeof(uint8_t));
			cudaEventRecord(start);
			for (int i = 0; i < z; ++i) {
				int ioffset = i * iBATCH;
				crypto_aead_encrypt_gpu_global_K200_FineOp << <blocks2, threads2, 0, GPUstreams[i] >> > (&d_cK[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K)], d_clen2, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
					&d_n[ioffset * CRYPTO_NPUBBYTES], &d_k[ioffset * CRYPTO_KEYBYTES]);
			}
			cudaEventRecord(stop);
			cudaEventSynchronize(stop);
			elapsed = 0.0f;
			cudaEventElapsedTime(&elapsed, start, stop);

			cudaEventRecord(start, 0);
			for (int i = 0; i < z; ++i) {
				int ioffset = i * iBATCH;
				cudaMemcpyAsync(&h_cK[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K)], &d_cK[ioffset * MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K)], iKsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
			}
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("K200 Fine", ct_K, h_cK, MAX_CIPHER_LENGTH(CRYPTO_ABYTES_K));
			total = memcpy_h2d + elapsed + memcpy_d2h;

			printf("%s%d\t%d\t\t%.6f\t%.6f\t%.6f\t%.f\n", "K200 Fine ", fineLevel, z, memcpy_h2d,
				memcpy_d2h, total, BATCH / (total / 1000));

#ifdef WRITEFILE
			fprintf(fpt, "%s%d, %d, (%u)(%u %u), %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.f,%.2f\n", "K200 Fine ", fineLevel, z, blocks2.x, threads2.x, threads2.y, (size * 2e-6) / total, total,
				cpu_tK / total, (size * 2e-6) / total * 8, memcpy_h2d, elapsed, memcpy_d2h, cpu_tK / elapsed, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_tK / 1000)));
#endif

			printf("\n======================================================================================================================================================\n");

			for (int i = 0; i < z; i++)
				CHECK(cudaStreamDestroy(GPUstreams[i]));
		}
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
	cudaFree(d_cS);
	cudaFree(d_cK);
	cudaFree(h_cS);
	cudaFree(h_cK);
	cudaFree(d_clen1);
	cudaFree(d_clen2);

	cudaEventDestroy(start);
	cudaEventDestroy(stop);
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();

}