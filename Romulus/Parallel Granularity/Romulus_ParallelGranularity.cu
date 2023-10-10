
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "CPUencrypt.c"
#include "romulusRef_GPU.h"
#include "romulusOp_GPU.c"
#include "operations.h"

__global__ void romulus_t_encrypt_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch
)
{
	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char Z[16];
		unsigned char CNT[7];
		unsigned char CNT_Z[7] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		const unsigned char* A;
		const unsigned char* M;
		const unsigned char* N;
		unsigned long long mlen_int;
		unsigned char LR[32];
		unsigned int i;

		(void)nsec;
		A = ad + offset_ad;
		M = m + offset_msg;
		N = npub + offset_nonce;

		reset_lfsr_gf56G(CNT);

		kdfG(K, Z, N, CNT_Z);
		*clen = mlen + 16;
		mlen_int = mlen;

		while (mlen != 0) {
			mlen = msg_encryptionTG(&M, &C, N, CNT, Z, mlen);
		}

		// T = hash(A||N||M)
		// We need to first pad A, N and C
		C = C - mlen_int;
		i = crypto_hash_vectorG(LR, A, adlen, C, mlen_int, N, CNT);


		//reset_lfsr_gf56(CNT);
		C = C + mlen_int;
		generate_tagTG(C, LR, CNT_Z, K);
	}
}


__global__ void romulus_m_encrypt_OpRef_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char s[16];
		unsigned char CNT[8];
		unsigned char T[16];
		const unsigned char* N;
		unsigned char w;
		unsigned long long xlen;

		skinny_ctrl l_skinny_ctrl;
		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G;

		(void)nsec;
		N = npub + offset_nonce;

		xlen = mlen;

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = 0;
		*(uint32_t*)(&s[4]) = 0;
		*(uint32_t*)(&s[8]) = 0;
		*(uint32_t*)(&s[12]) = 0;

#else

		s[0] = 0;
		s[1] = 0;
		s[2] = 0;
		s[3] = 0;
		s[4] = 0;
		s[5] = 0;
		s[6] = 0;
		s[7] = 0;
		s[8] = 0;
		s[9] = 0;
		s[10] = 0;
		s[11] = 0;
		s[12] = 0;
		s[13] = 0;
		s[14] = 0;
		s[15] = 0;

#endif

		reset_lfsr_gf56OG(CNT);

		w = 48;

		if (adlen == 0) {
			w = w ^ 2;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) == 0) {
			w = w ^ 8;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) < 16) {
			w = w ^ 2;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) == 16) {
			w = w ^ 0;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else {
			w = w ^ 10;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}

		if (adlen == 0) { // AD is an empty string
			lfsr_gf56OG(CNT);
		}
		else while (adlen > 0) {
			/*printf("Ref -> ");
			for (int i = 0; i < 15; ++i) printf("%x", s[i]);*/
			adlen = ad_encryptionOG(&A, s, K, adlen, CNT, 40, &l_skinny_ctrl);

		}

		if ((w & 8) == 0) {
			xlen = ad2msg_encryptionOG(&M, CNT, s, k, 44, xlen, &l_skinny_ctrl);
		}
		else if (mlen == 0) {
			lfsr_gf56OG(CNT);
		}
		while (xlen > 0) {
			xlen = ad_encryptionOG(&M, s, K, xlen, CNT, 44, &l_skinny_ctrl);
		}
		nonce_encryptionOG(N, CNT, s, K, w, &l_skinny_ctrl);

		// Tag generation
		g8AG(s, T);

		M = M - mlen;

		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1G;

		reset_lfsr_gf56OG(CNT);

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = *(uint32_t*)(&T[0]);
		*(uint32_t*)(&s[4]) = *(uint32_t*)(&T[4]);
		*(uint32_t*)(&s[8]) = *(uint32_t*)(&T[8]);
		*(uint32_t*)(&s[12]) = *(uint32_t*)(&T[12]);

#else

		s[0] = T[0];
		s[1] = T[1];
		s[2] = T[2];
		s[3] = T[3];
		s[4] = T[4];
		s[5] = T[5];
		s[6] = T[6];
		s[7] = T[7];
		s[8] = T[8];
		s[9] = T[9];
		s[10] = T[10];
		s[11] = T[11];
		s[12] = T[12];
		s[13] = T[13];
		s[14] = T[14];
		s[15] = T[15];

#endif

		* clen = mlen + 16;

		if (mlen > 0) {
			nonce_encryptionOG(N, CNT, s, K, 36, &l_skinny_ctrl);

			while (mlen > 16) {
				mlen = msg_encryptionOG(&M, &C, N, CNT, s, K, 36, mlen, &l_skinny_ctrl);
			}

			rho_ud16G(M, C, s, mlen);

			C = C + mlen;
			M = M + mlen;

		}

		// Tag Concatenation
		C[0] = T[0];
		C[1] = T[1];
		C[2] = T[2];
		C[3] = T[3];
		C[4] = T[4];
		C[5] = T[5];
		C[6] = T[6];
		C[7] = T[7];
		C[8] = T[8];
		C[9] = T[9];
		C[10] = T[10];
		C[11] = T[11];
		C[12] = T[12];
		C[13] = T[13];
		C[14] = T[14];
		C[15] = T[15];

		C = C - *clen;

	}
}

__global__ void romulus_n_encrypt_OpRef_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char s[16];
		unsigned char CNT[8];
		const unsigned char* A;
		const unsigned char* M;
		const unsigned char* N;

		skinny_ctrl ctrl;
		ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G;

		(void)nsec;
		A = ad + offset_ad;
		M = m + offset_msg;
		N = npub + offset_nonce;

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = 0;
		*(uint32_t*)(&s[4]) = 0;
		*(uint32_t*)(&s[8]) = 0;
		*(uint32_t*)(&s[12]) = 0;

#else

		s[0] = 0;
		s[1] = 0;
		s[2] = 0;
		s[3] = 0;
		s[4] = 0;
		s[5] = 0;
		s[6] = 0;
		s[7] = 0;
		s[8] = 0;
		s[9] = 0;
		s[10] = 0;
		s[11] = 0;
		s[12] = 0;
		s[13] = 0;
		s[14] = 0;
		s[15] = 0;

#endif

		reset_lfsr_gf56OG(CNT);

		if (adlen == 0) { // AD is an empty string
			lfsr_gf56OG(CNT);
			nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
		}
		else while (adlen > 0) {
			if (adlen < 16) { // The last block of AD is odd and incomplete
				adlen = ad_encryption_ud16G(&A, s, adlen, CNT);
				nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
			}
			else if (adlen == 16) { // The last block of AD is odd and complete
				adlen = ad_encryption_eq16G(&A, s, CNT);
				nonce_encryptionOG(N, CNT, s, K, 0x18, &ctrl);
			}
			else if (adlen < 32) { // The last block of AD is even and incomplete
				adlen = ad_encryption_ov16G(&A, s, K, adlen, CNT, 0x08, &ctrl);
				nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
			}
			else if (adlen == 32) { // The last block of AD is even and complete
				adlen = ad_encryption_eqov32G(&A, s, K, adlen, CNT, 0x08, &ctrl);
				nonce_encryptionOG(N, CNT, s, K, 0x18, &ctrl);
			}
			else { // A normal full pair of blocks of AD
				adlen = ad_encryption_eqov32G(&A, s, k, adlen, CNT, 0x08, &ctrl);
			}
		}

		ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1G;

		reset_lfsr_gf56OG(CNT);

		*clen = mlen + 16;

		if (mlen == 0) { // M is an empty string
			lfsr_gf56OG(CNT);
			nonce_encryptionOG(N, CNT, s, K, 0x15, &ctrl);
		}
		else while (mlen > 0) {
			if (mlen < 16) { // The last block of M is incomplete
				mlen = msg_encryption_ud16G(&M, &C, N, CNT, s, K, 0x15, mlen, &ctrl);
			}
			else if (mlen == 16) { // The last block of M is complete
				mlen = msg_encryption_eqov16G(&M, &C, N, CNT, s, K, 0x14, mlen, &ctrl);
			}
			else { // A normal full message block
				mlen = msg_encryption_eqov16G(&M, &C, N, CNT, s, K, 0x04, mlen, &ctrl);
			}
		}

		// Tag generation
		generate_tagOG(&C, s, clen);

	}
}

__global__ void romulus_m_encrypt_Op_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(m) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(ad) + offset_ad;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char s[16];
		unsigned char CNT[8];
		unsigned char T[16];
		const unsigned char* N;
		unsigned char w;
		unsigned long long xlen;

		skinny_ctrl l_skinny_ctrl;
		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G_Op;

		(void)nsec;
		N = npub + offset_nonce;

		xlen = mlen;

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = 0;
		*(uint32_t*)(&s[4]) = 0;
		*(uint32_t*)(&s[8]) = 0;
		*(uint32_t*)(&s[12]) = 0;

#else

		s[0] = 0;
		s[1] = 0;
		s[2] = 0;
		s[3] = 0;
		s[4] = 0;
		s[5] = 0;
		s[6] = 0;
		s[7] = 0;
		s[8] = 0;
		s[9] = 0;
		s[10] = 0;
		s[11] = 0;
		s[12] = 0;
		s[13] = 0;
		s[14] = 0;
		s[15] = 0;

#endif

		reset_lfsr_gf56OG(CNT);

		w = 48;

		if (adlen == 0) {
			w = w ^ 2;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) == 0) {
			w = w ^ 8;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) < 16) {
			w = w ^ 2;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else if (adlen % (32) == 16) {
			w = w ^ 0;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}
		else {
			w = w ^ 10;
			if (xlen == 0) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 0) {
				w = w ^ 4;
			}
			else if (xlen % (32) < 16) {
				w = w ^ 1;
			}
			else if (xlen % (32) == 16) {
				w = w ^ 0;
			}
			else {
				w = w ^ 5;
			}
		}

		if (adlen == 0) { // AD is an empty string
			lfsr_gf56OG(CNT);

		}
		else while (adlen > 0) {
			/*		printf("Op -> ");
					for (int i = 0; i < 15; ++i) printf("%x", s[i]);*/
			adlen = ad_encryptionOG(&A, s, K, adlen, CNT, 40, &l_skinny_ctrl);
		}

		if ((w & 8) == 0) {
			xlen = ad2msg_encryptionOG(&M, CNT, s, k, 44, xlen, &l_skinny_ctrl);
		}
		else if (mlen == 0) {
			lfsr_gf56OG(CNT);
		}
		while (xlen > 0) {
			xlen = ad_encryptionOG(&M, s, K, xlen, CNT, 44, &l_skinny_ctrl);
		}
		nonce_encryptionOG(N, CNT, s, K, w, &l_skinny_ctrl);

		// Tag generation
		g8AG(s, T);
		M = M - mlen;

		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1G_Op;

		reset_lfsr_gf56OG(CNT);

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = *(uint32_t*)(&T[0]);
		*(uint32_t*)(&s[4]) = *(uint32_t*)(&T[4]);
		*(uint32_t*)(&s[8]) = *(uint32_t*)(&T[8]);
		*(uint32_t*)(&s[12]) = *(uint32_t*)(&T[12]);


#else

		s[0] = T[0];
		s[1] = T[1];
		s[2] = T[2];
		s[3] = T[3];
		s[4] = T[4];
		s[5] = T[5];
		s[6] = T[6];
		s[7] = T[7];
		s[8] = T[8];
		s[9] = T[9];
		s[10] = T[10];
		s[11] = T[11];
		s[12] = T[12];
		s[13] = T[13];
		s[14] = T[14];
		s[15] = T[15];

#endif

		* clen = mlen + 16;

		if (mlen > 0) {
			nonce_encryptionOG(N, CNT, s, K, 36, &l_skinny_ctrl);

			while (mlen > 16) {
				mlen = msg_encryptionOG(&M, &C, N, CNT, s, K, 36, mlen, &l_skinny_ctrl);
			}

			rho_ud16G(M, C, s, mlen);
			C = C + mlen;
			M = M + mlen;

		}

		// Tag Concatenation
		C[0] = T[0];
		C[1] = T[1];
		C[2] = T[2];
		C[3] = T[3];
		C[4] = T[4];
		C[5] = T[5];
		C[6] = T[6];
		C[7] = T[7];
		C[8] = T[8];
		C[9] = T[9];
		C[10] = T[10];
		C[11] = T[11];
		C[12] = T[12];
		C[13] = T[13];
		C[14] = T[14];
		C[15] = T[15];

		C = C - *clen;
	}
}

__global__ void romulus_n_encrypt_Op_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char s[16];
		unsigned char CNT[8];
		const unsigned char* A;
		const unsigned char* M;
		const unsigned char* N;

		skinny_ctrl ctrl;
		ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G_Op;

		(void)nsec;
		A = ad + offset_ad;
		M = m + offset_msg;
		N = npub + offset_nonce;

#ifdef ___ENABLE_WORD_CAST

		* (uint32_t*)(&s[0]) = 0;
		*(uint32_t*)(&s[4]) = 0;
		*(uint32_t*)(&s[8]) = 0;
		*(uint32_t*)(&s[12]) = 0;

#else

		s[0] = 0;
		s[1] = 0;
		s[2] = 0;
		s[3] = 0;
		s[4] = 0;
		s[5] = 0;
		s[6] = 0;
		s[7] = 0;
		s[8] = 0;
		s[9] = 0;
		s[10] = 0;
		s[11] = 0;
		s[12] = 0;
		s[13] = 0;
		s[14] = 0;
		s[15] = 0;

#endif

		reset_lfsr_gf56OG(CNT);

		if (adlen == 0) { // AD is an empty string
			lfsr_gf56OG(CNT);
			nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
		}
		else while (adlen > 0) {
			if (adlen < 16) { // The last block of AD is odd and incomplete
				adlen = ad_encryption_ud16G(&A, s, adlen, CNT);
				nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
			}
			else if (adlen == 16) { // The last block of AD is odd and complete
				adlen = ad_encryption_eq16G(&A, s, CNT);
				nonce_encryptionOG(N, CNT, s, K, 0x18, &ctrl);
			}
			else if (adlen < 32) { // The last block of AD is even and incomplete
				adlen = ad_encryption_ov16G(&A, s, K, adlen, CNT, 0x08, &ctrl);
				nonce_encryptionOG(N, CNT, s, K, 0x1a, &ctrl);
			}
			else if (adlen == 32) { // The last block of AD is even and complete
				adlen = ad_encryption_eqov32G(&A, s, K, adlen, CNT, 0x08, &ctrl);
				nonce_encryptionOG(N, CNT, s, K, 0x18, &ctrl);
			}
			else { // A normal full pair of blocks of AD
				adlen = ad_encryption_eqov32G(&A, s, k, adlen, CNT, 0x08, &ctrl);
			}
		}

		ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1G_Op;

		reset_lfsr_gf56OG(CNT);

		*clen = mlen + 16;

		if (mlen == 0) { // M is an empty string
			lfsr_gf56OG(CNT);
			nonce_encryptionOG(N, CNT, s, K, 0x15, &ctrl);
		}
		else while (mlen > 0) {
			if (mlen < 16) { // The last block of M is incomplete
				mlen = msg_encryption_ud16G(&M, &C, N, CNT, s, K, 0x15, mlen, &ctrl);
			}
			else if (mlen == 16) { // The last block of M is complete
				mlen = msg_encryption_eqov16G(&M, &C, N, CNT, s, K, 0x14, mlen, &ctrl);
			}
			else { // A normal full message block
				mlen = msg_encryption_eqov16G(&M, &C, N, CNT, s, K, 0x04, mlen, &ctrl);
			}
		}

		// Tag generation
		generate_tagOG(&C, s, clen);

	}
}

__global__ void romulus_t_encrypt_Op_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub,
	const uint8_t * k, int Batch
)
{
	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		unsigned char Z[16];
		unsigned char CNT[7];
		unsigned char CNT_Z[7] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		const unsigned char* A;
		const unsigned char* M;
		const unsigned char* N;
		unsigned long long mlen_int;
		unsigned char LR[32];
		unsigned int i;

		(void)nsec;
		A = ad + offset_ad;
		M = m + offset_msg;
		N = npub + offset_nonce;

		reset_lfsr_gf56G(CNT);

		kdfG_Op(K, Z, N, CNT_Z);
		*clen = mlen + 16;
		mlen_int = mlen;

		while (mlen != 0) {
			mlen = msg_encryptionTG_Op(&M, &C, N, CNT, Z, mlen);
		}

		// T = hash(A||N||M)
		// We need to first pad A, N and C
		C = C - mlen_int;
		i = crypto_hash_vectorG_Op(LR, A, adlen, C, mlen_int, N, CNT);


		//reset_lfsr_gf56(CNT);
		C = C + mlen_int;
		generate_tagTG(C, LR, CNT_Z, K);
	}
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	char writeFile[100];
	char version[1];

	strcpy(writeFile, "Romulus_PG_");
	sprintf(version, "%s", ROMULUS_VER);
	strcat(writeFile, version);
	strcat(writeFile, ".csv");

	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	////64K, 256K, 1M, 4M, 10M ->64000,,256000,1000000,4000000,16000000 
	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ctM, * ctN, * ctT;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clenM, clenN, clenT;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_tM = 0, cpu_tT = 0, cpu_tN = 0;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ctM, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)& ctN, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)& ctT, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		int (*CPU)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*, unsigned long long,
			const unsigned char*, const unsigned char*, const unsigned char*);
		//Print Host Time
		printf("\nVersion \tLatency (ms)\t\t\tAEAD/s\n");

		uint8_t* ct;
		uint64_t clen;
		char* name;
		if (ROMULUS_VER == "M") {
			CPU = &romulus_m_encrypt_Op;
			ct = ctM;
			clen = clenM;
			name = "Host M";

		}
		else if (ROMULUS_VER == "N") {
			CPU = &romulus_n_encrypt_Op;
			ct = ctN;
			clen = clenN;
			name = "Host N";

		}
		else {
			CPU = &romulus_t_encrypt;
			ct = ctT;
			clen = clenT;
			name = "Host T  ";

		}

		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);

		for (int i = 0; i < BATCH[z]; i++) {
			int result = CPU(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
			print('c', ct + (i * clen), clen);
#endif
		}
		QueryPerformanceCounter(&t2);
		double cpu_t = 0;
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", name, BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif

		printf("%s:\t %.6f ms\t\t\t\t%.f\n", name, cpu_t, BATCH[z] / (cpu_t / 1000));

		if (ROMULUS_VER == "M")
			cpu_tM = cpu_t;
		else if (ROMULUS_VER == "N")
			cpu_tN = cpu_t;
		else
			cpu_tT = cpu_t;


		//GPU implementation
		uint8_t * d_n, *d_k, *d_a, *d_m, *d_cM, *h_cM, *h_cN, *d_cN, *d_cT, *h_cT;
		uint64_t * d_clen1, *d_clen2, *d_clen3;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)& h_cM, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMallocHost((void**)& h_cN, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMallocHost((void**)& h_cT, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMalloc((void**)& d_cM, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_cN, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_cT, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_n, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
		cudaMalloc((void**)& d_k, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
		cudaMalloc((void**)& d_m, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));				//Message
		cudaMalloc((void**)& d_a, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
		cudaMallocHost((void**)& d_clen1, sizeof(uint64_t));
		cudaMallocHost((void**)& d_clen2, sizeof(uint64_t));
		cudaMallocHost((void**)& d_clen3, sizeof(uint64_t));

		//Memory initialisation
		memset(h_cM, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		memset(h_cN, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		memset(h_cT, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_cM, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_cN, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_cT, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
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

		void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*, int);


		//Parallel Granularity
		for (int i = 1; i < 1025; i *= 2) {
			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);

			for (int a = 1; a < 3; a++) {

				uint8_t* d_c, * h_c, * ct;
				uint64_t* d_clen;

				char* name;

				if (ROMULUS_VER == "M") {
					kernel = ((a == 1) ? &romulus_m_encrypt_OpRef_GPU : &romulus_m_encrypt_Op_GPU);
					d_c = d_cM;
					h_c = h_cM;
					ct = ctM;
					d_clen = d_clen1;
					name = ((a == 1) ? "M_OpRef GPU" : "M_Op GPU");
				}
				else if (ROMULUS_VER == "N") {
					kernel = ((a == 1) ? &romulus_n_encrypt_OpRef_GPU : &romulus_n_encrypt_Op_GPU);
					d_c = d_cN;
					h_c = h_cN;
					ct = ctN;
					d_clen = d_clen2;
					name = ((a == 1) ? "N_OpRef GPU" : "N_Op GPU");
				}
				else {
					kernel = ((a == 1) ? &romulus_t_encrypt_GPU : &romulus_t_encrypt_Op_GPU);
					d_c = d_cT;
					h_c = h_cT;
					ct = ctT;
					d_clen = d_clen3;
					name = ((a == 1) ? "T GPU" : "T_Op GPU");
				}

				cudaEventRecord(start, 0);
				kernel << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				float kernel = 0;
				cudaEventElapsedTime(&kernel, start, stop);

				//Memory Copy from D2H
				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				float memcpy_d2h = 0;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);

				double cpu_t = ((ROMULUS_VER == "M") ? cpu_tM : ((ROMULUS_VER == "N") ? cpu_tN : cpu_tT));
				checkResult(name, ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
				PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], name);
#else
				PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], name);
#endif

				memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			}

		}

		//Free Memory
		//Host memory
		cudaFree(nonce);
		cudaFree(key);
		cudaFree(msg);
		cudaFree(ad);
		cudaFree(ctM);
		cudaFree(ctN);
		cudaFree(ctT);

		//Device memory
		cudaFree(d_n);
		cudaFree(d_k);
		cudaFree(d_a);
		cudaFree(d_m);
		cudaFree(d_cM);
		cudaFree(d_cN);
		cudaFree(d_cT);
		cudaFree(h_cM);
		cudaFree(h_cN);
		cudaFree(h_cT);
		cudaFree(d_clen1);
		cudaFree(d_clen2);
		cudaFree(d_clen3);

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




