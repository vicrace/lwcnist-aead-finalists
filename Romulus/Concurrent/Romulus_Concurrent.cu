
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "params.h"
#include "CPUencrypt.c"
#include "romulusRef_GPU.h"
#include "romulusOp_GPU.c"
#include "operations.h"


__global__ void romulus_t_encrypt_GPU(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k
)
{
	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k
)
{
	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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


/////Transpose
__global__ void romulus_t_encrypt_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k
)
{
	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;


		unsigned char Z[16];
		unsigned char CNT[7];
		unsigned char CNT_Z[7] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		unsigned long long mlen_int;
		unsigned char LR[32];
		unsigned int i;
		(void)nsec;


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

__global__ void romulus_m_encrypt_OpRef_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_KEYBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_KEYBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;


		unsigned char s[16];
		unsigned char CNT[8];
		unsigned char T[16];
		unsigned char w;
		unsigned long long xlen;

		skinny_ctrl l_skinny_ctrl;
		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G;

		(void)nsec;

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

__global__ void romulus_n_encrypt_OpRef_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;


		unsigned char s[16];
		unsigned char CNT[8];
		skinny_ctrl ctrl;
		ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G;

		(void)nsec;

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


__global__ void romulus_m_encrypt_Op_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;


		unsigned char s[16];
		unsigned char CNT[8];
		unsigned char T[16];
		unsigned char w;
		unsigned long long xlen;

		skinny_ctrl l_skinny_ctrl;
		l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G_Op;

		(void)nsec;

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

__global__ void romulus_n_encrypt_Op_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;


		unsigned char s[16];
		unsigned char CNT[8];
		skinny_ctrl ctrl;
		ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12G_Op;

		(void)nsec;

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

__global__ void romulus_t_encrypt_Op_GPU_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub,
	const uint8_t* k
)
{
	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;

		unsigned char Z[16];
		unsigned char CNT[7];
		unsigned char CNT_Z[7] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		unsigned long long mlen_int;
		unsigned char LR[32];
		unsigned int i;

		(void)nsec;

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

	strcpy(writeFile, "Romulus_Concurent_");
	sprintf(version, "%s", ROMULUS_VER);
	strcat(writeFile, version);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");

	fprintf(fpt, "Version, Dimension, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	printf("\nSize Implementation : %d\n", BATCH);

	uint8_t* nonce, * key, * msg, * ad, * ctM, * ctN, * ctT;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clenM, clenN, clenT;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_tM = 0, cpu_tT = 0, cpu_tN = 0;

	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ctM, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMallocHost((void**)& ctN, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMallocHost((void**)& ctT, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));

	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);

	int (*CPU)(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*, unsigned long long,
		const unsigned char*, const unsigned char*, const unsigned char*);
	printf("Version\t\tCKernel\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");

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

	for (int i = 0; i < BATCH; i++) {
		int result = CPU(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}
	QueryPerformanceCounter(&t2);
	double cpu_t = 0;
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", name, 0, 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif

	printf("%s\tSerial\t\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", name, 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));


	if (ROMULUS_VER == "M")
		cpu_tM = cpu_t;
	else if (ROMULUS_VER == "N")
		cpu_tN = cpu_t;
	else
		cpu_tT = cpu_t;

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

	uint8_t * d_n, *d_k, *d_a, *d_m, *d_cM, *h_cM, *h_cN, *d_cN, *d_cT, *h_cT;
	uint64_t * d_clen1, *d_clen2, *d_clen3;
	cudaEvent_t start, stop;

	cudaEventCreate(&start);
	cudaEventCreate(&stop);

	//Memory Allocation - Device
	cudaMallocHost((void**)& h_cM, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
	cudaMallocHost((void**)& h_cN, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
	cudaMallocHost((void**)& h_cT, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
	cudaMalloc((void**)& d_cM, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_cN, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_cT, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_n, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
	cudaMalloc((void**)& d_k, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
	cudaMalloc((void**)& d_m, BATCH * (uint64_t)mlen * sizeof(uint8_t));				//Message
	cudaMalloc((void**)& d_a, BATCH * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
	cudaMallocHost((void**)& d_clen1, sizeof(uint64_t));
	cudaMallocHost((void**)& d_clen2, sizeof(uint64_t));
	cudaMallocHost((void**)& d_clen3, sizeof(uint64_t));

	//Memory initialisation
	memset(h_cM, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	memset(h_cN, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	memset(h_cT, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_cM, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_cN, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_cT, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
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
			size_t iCsize = iBATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t);

			for (int i = 64; i < 1025; i *= 2) {

				float elapsed, memcpy_d2h, total;

				for (int a = 1; a < 5; a++) {

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
					else if ((a == 3 && ROMULUS_VER == "T") || (a == 4 && ROMULUS_VER != "T")) {
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

					dim3 threads(i);
					double temp = (double)iBATCH / (double)i;
					dim3 blocks(ceil(temp));
					if ((ROMULUS_VER != "T" && a > 3) || (ROMULUS_VER == "T" && a > 2)) {
						threads.y = i;
						temp = (double)iBATCH / ((double)threads.x * (double)threads.y);
						blocks.x = ceil(temp);
						blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
					}

					uint8_t* d_c, * h_c, * ct;
					uint64_t* d_clen;
					char* kernelName;

					if (ROMULUS_VER == "M") {
						kernel = ((a == 1) ? &romulus_m_encrypt_OpRef_GPU : ((a == 2) ? &romulus_m_encrypt_Op_GPU
							: ((a == 3) ? &romulus_m_encrypt_OpRef_GPU_Trans : &romulus_m_encrypt_Op_GPU_Trans)));
						d_c = d_cM;
						h_c = h_cM;
						ct = ctM;
						d_clen = d_clen1;
						kernelName = ((a == 1) ? "M Ref       " : ((a == 2) ? "M_Op        " : ((a == 3) ? "M_OpRef Trans " : "M_Op Trans")));
					}
					else if (ROMULUS_VER == "N") {
						kernel = ((a == 1) ? &romulus_n_encrypt_OpRef_GPU : ((a == 2) ? &romulus_n_encrypt_Op_GPU
							: ((a == 3) ? &romulus_n_encrypt_OpRef_GPU_Trans : &romulus_n_encrypt_Op_GPU_Trans)));
						d_c = d_cN;
						h_c = h_cN;
						ct = ctN;
						d_clen = d_clen2;
						kernelName = ((a == 1) ? "N Ref       " : ((a == 2) ? "N_Op        " : ((a == 3) ? "N Ref Trans" : "N_Op Trans")));
					}
					else {
						kernel = ((a == 1) ? &romulus_t_encrypt_GPU : ((a == 2) ? &romulus_t_encrypt_Op_GPU : ((a == 3) ? &romulus_t_encrypt_GPU_Trans
							: &romulus_t_encrypt_Op_GPU_Trans)));
						d_c = d_cT;
						h_c = h_cT;
						ct = ctT;
						d_clen = d_clen3; 
						kernelName = ((a == 1) ? "T        " : ((a == 2) ? "T_Op        " : ((a == 3) ? "TRef Trans" : "T_Op Trans")));
					}


					//Kernel execution
					memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
					cudaEventRecord(start);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						kernel << <blocks, threads, 0, GPUstreams[i] >> > (&d_c[ioffset * MAX_CIPHER_LENGTH], d_clen, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
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
						cudaMemcpyAsync(&h_c[ioffset * MAX_CIPHER_LENGTH], &d_c[ioffset * MAX_CIPHER_LENGTH], iCsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
					}
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					memcpy_d2h = 0.0f;
					cudaEventElapsedTime(&memcpy_d2h, start, stop);

					checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);

					double Ttime = 0;
					if (a < 3)
						total = memcpy_h2d + elapsed + memcpy_d2h;
					else {
						total = memcpy_h2d + trans + elapsed + memcpy_d2h;
						Ttime = trans;
					}

					printf("%s\t%d\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t\t%.f\n", kernelName, z, threads.x, memcpy_h2d,
						memcpy_d2h,total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));

#ifdef WRITEFILE
					fprintf(fpt, "%s,%d, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, z, threads.x, total,
						memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif
				}
			}
		}
		printf("======================================================================================================================\n");
		for (int i = 0; i < z; i++)
			cudaStreamDestroy(GPUstreams[i]);
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

#ifdef WRITEFILE
	fclose(fpt);
#endif

	cudaDeviceReset();
	return 0;
}




