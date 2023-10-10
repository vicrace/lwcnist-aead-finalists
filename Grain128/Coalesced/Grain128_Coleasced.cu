
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "params.h"
#include "operations.h"
#include "grainRef.h"
#include "grainOp.h"

/* This implementation assumes that the most significant bit is processed first,
	 * in a byte. The optimized version however, processes the lsb first.
	 * In order to give the same test vectors, we here change the interpretation of the bits.
	 */
int crypto_aead_encrypt_ref(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* mp, unsigned long long mlen,
	const unsigned char* adp, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npubp,
	const unsigned char* kp) {

	unsigned char* m = (unsigned char*)malloc(mlen);;
	unsigned char* ad = (unsigned char*)malloc(mlen);;
	unsigned char npub[12];
	unsigned char k[16];

	for (unsigned long long i = 0; i < mlen; i++) {
		m[i] = swapsb(mp[i]);
	}
	for (unsigned long long i = 0; i < adlen; i++) {
		ad[i] = swapsb(adp[i]);
	}
	for (unsigned long long i = 0; i < 12; i++) {
		npub[i] = swapsb(npubp[i]);
	}
	for (unsigned long long i = 0; i < 16; i++) {
		k[i] = swapsb(kp[i]);
	}

	grain_state grain;
	grain_data data;

	init_grain(&grain, k, npub);
	init_data(&data, m, mlen);
	*clen = 0;

	// authenticate adlen by prepeding to ad, using DER encoding
	unsigned char* ader;
	int aderlen = encode_der(adlen, &ader);
	// append ad to buffer
	ader = (unsigned char*)realloc(ader, aderlen + adlen);
	memcpy(ader + aderlen, ad, adlen);

	unsigned long long ad_cnt = 0;
	unsigned char adval = 0;

	/* accumulate tag for associated data only */
	for (unsigned long long i = 0; i < aderlen + adlen; i++) {
		/* every second bit is used for keystream, the others for MAC */
		for (int j = 0; j < 16; j++) {
			unsigned char z_next = next_z(&grain, 0, 0);
			if (j % 2 == 0) {
				// do not encrypt
			}
			else {
				adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
				if (adval) {
					accumulate(&grain);
				}
				auth_shift(grain.auth_sr, z_next);
				ad_cnt++;
			}
		}
	}

	/*printf("CPU\n");
	uint64_t i;
	printf("lfsr[%d]=", 128);
	for (i = 0; i < 128; ++i) printf("%x", grain.lfsr[i]);
	printf("\n");

	printf("nfsr[%d]=", 128);
	for (i = 0; i < 128; ++i) printf("%x", grain.nfsr[i]);
	printf("\n");

	printf("acc[%d]=", 64);
	for (i = 0; i < 64; ++i) printf("%x", grain.auth_acc[i]);
	printf("\n");

	printf("sr[%d]=", 64);
	for (i = 0; i < 64; ++i) printf("%x", grain.auth_sr[i]);
	printf("\n");*/

	free(ader);

	unsigned long long ac_cnt = 0;
	unsigned long long m_cnt = 0;
	unsigned long long c_cnt = 0;
	unsigned char cc = 0;

	// generate keystream for message
	for (unsigned long long i = 0; i < mlen; i++) {
		// every second bit is used for keystream, the others for MAC
		cc = 0;
		for (int j = 0; j < 16; j++) {
			unsigned char z_next = next_z(&grain, 0, 0);
			if (j % 2 == 0) {
				// transform it back to 8 bits per byte
				cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
				c_cnt++;
			}
			else {
				if (data.message[ac_cnt++] == 1) {
					accumulate(&grain);
				}
				auth_shift(grain.auth_sr, z_next);
			}
		}
		c[i] = swapsb(cc);
		*clen += 1;
	}

	// generate unused keystream bit
	next_z(&grain, 0, 0);
	// the 1 in the padding means accumulation
	accumulate(&grain);

	/* append MAC to ciphertext */
	unsigned long long acc_idx = 0;
	for (unsigned long long i = mlen; i < mlen + 8; i++) {
		unsigned char acc = 0;
		// transform back to 8 bits per byte
		for (int j = 0; j < 8; j++) {
			acc |= grain.auth_acc[8 * acc_idx + j] << (7 - j);
		}
		c[i] = swapsb(acc);
		acc_idx++;
		*clen += 1;
	}

	free(data.message);
	free(m);
	free(ad);

	return 0;
}


__global__ void grain_encrypt_ref_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * mp, uint64_t mlen,
	const uint8_t * adp, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npubp,
	const uint8_t * kp) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(mp) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(adp) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npubp) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(kp) + offset_key;

		unsigned char* m = (unsigned char*)malloc(mlen);;
		unsigned char* ad = (unsigned char*)malloc(mlen);;
		unsigned char npub[12];
		unsigned char k[16];

		/*uint64_t i;
		printf("K[%d]=", (int)CRYPTO_KEYBYTES);
		for (i = 0; i < CRYPTO_KEYBYTES; ++i) printf("%x", K[i]);
		printf("\n");

		printf("A[%d]=", (int)adlen);
		for (i = 0; i < adlen; ++i) printf("%x", A[i]);
		printf("\n");

		printf("M[%d]=", (int)mlen);
		for (i = 0; i < mlen; ++i) printf("%x", M[i]);
		printf("\n");

		printf("N[%d]=", (int)CRYPTO_NPUBBYTES);
		for (i = 0; i < CRYPTO_NPUBBYTES; ++i) printf("%x", N[i]);
		printf("\n");*/


		for (unsigned long long i = 0; i < mlen; i++) {
			m[i] = swapsbG(M[i]);
		}
		for (unsigned long long i = 0; i < adlen; i++) {
			ad[i] = swapsbG(A[i]);
		}
		for (unsigned long long i = 0; i < 12; i++) {
			npub[i] = swapsbG(N[i]);
		}
		for (unsigned long long i = 0; i < 16; i++) {
			k[i] = swapsbG(K[i]);
		}

		grain_state grain;
		grain_data data;

		init_grainG(&grain, k, npub);
		init_dataG(&data, m, mlen);
		*clen = 0;

		// authenticate adlen by prepeding to ad, using DER encoding
		unsigned char* ader;
		int aderlen = encode_derG(adlen, &ader);
		// append ad to buffer
		//ader = (unsigned char*)malloc(aderlen + adlen);
		memcpy(ader + aderlen, ad, adlen);

		unsigned long long ad_cnt = 0;
		unsigned char adval = 0;

		/* accumulate tag for associated data only */
		for (unsigned long long i = 0; i < aderlen + adlen; i++) {
			/* every second bit is used for keystream, the others for MAC */
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// do not encrypt
				}
				else {
					adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
					if (adval) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
					ad_cnt++;
				}
			}
		}


		//printf("GPU\n");
		//uint64_t i;
		//printf("lfsr[%d]=", 128);
		//for (i = 0; i < 128; ++i) printf("%x", grain.lfsr[i]);
		//printf("\n");

		//printf("nfsr[%d]=", 128);
		//for (i = 0; i < 128; ++i) printf("%x", grain.nfsr[i]);
		//printf("\n");

		//printf("acc[%d]=", 64);
		//for (i = 0; i < 64; ++i) printf("%x", grain.auth_acc[i]);
		//printf("\n");

		//printf("sr[%d]=", 64);
		//for (i = 0; i < 64; ++i) printf("%x", grain.auth_sr[i]);
		//printf("\n"); 

		free(ader);

		unsigned long long ac_cnt = 0;
		unsigned long long m_cnt = 0;
		unsigned long long c_cnt = 0;
		unsigned char cc = 0;

		// generate keystream for message
		for (unsigned long long i = 0; i < mlen; i++) {
			// every second bit is used for keystream, the others for MAC
			cc = 0;
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// transform it back to 8 bits per byte
					cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
					c_cnt++;
				}
				else {
					if (data.message[ac_cnt++] == 1) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
				}
			}
			C[i] = swapsbG(cc);
			*clen += 1;
		}

		// generate unused keystream bit
		next_zG(&grain, 0, 0);
		// the 1 in the padding means accumulation
		accumulateG(&grain);

		/* append MAC to ciphertext */
		unsigned long long acc_idx = 0;
		for (unsigned long long i = mlen; i < mlen + 8; i++) {
			unsigned char acc = 0;
			// transform back to 8 bits per byte
			for (int j = 0; j < 8; j++) {
				acc |= grain.auth_acc[8 * acc_idx + j] << (7 - j);
			}
			C[i] = swapsbG(acc);
			acc_idx++;
			*clen += 1;
		}

		free(data.message);
		free(m);
		free(ad);
	}
}

__global__ void grain_encrypt_MemOp_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * mp, uint64_t mlen,
	const uint8_t * adp, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npubp,
	const uint8_t * kp) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<uint8_t*>(mp) + offset_msg;
		uint8_t* A = const_cast<uint8_t*>(adp) + offset_ad;
		uint8_t* N = const_cast<uint8_t*>(npubp) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(kp) + offset_key;

		unsigned char* m = (unsigned char*)malloc(mlen);;
		unsigned char* ad = (unsigned char*)malloc(mlen);;
		unsigned char npub[12];
		unsigned char k[16];


		for (unsigned long long i = 0; i < mlen; i++) {
			m[i] = swapsbG(M[i]);
		}
		for (unsigned long long i = 0; i < adlen; i++) {
			ad[i] = swapsbG(A[i]);
		}
		for (unsigned long long i = 0; i < 12; i++) {
			npub[i] = swapsbG(N[i]);
		}
		for (unsigned long long i = 0; i < 16; i++) {
			k[i] = swapsbG(K[i]);
		}

		grain_state grain;
		grain_data data;

		init_grain_MemOp(&grain, k, npub);
		init_dataG(&data, m, mlen);
		*clen = 0;

		// authenticate adlen by prepeding to ad, using DER encoding
		unsigned char* ader;
		int aderlen = encode_derG(adlen, &ader);
		// append ad to buffer
		//ader = (unsigned char*)malloc(aderlen + adlen);
		memcpy(ader + aderlen, ad, adlen);

		unsigned long long ad_cnt = 0;
		unsigned char adval = 0;

		/* accumulate tag for associated data only */
		for (unsigned long long i = 0; i < aderlen + adlen; i++) {
			/* every second bit is used for keystream, the others for MAC */
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// do not encrypt
				}
				else {
					adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
					if (adval) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
					ad_cnt++;
				}
			}
		}


		free(ader);

		unsigned long long ac_cnt = 0;
		unsigned long long m_cnt = 0;
		unsigned long long c_cnt = 0;
		unsigned char cc = 0;

		// generate keystream for message
		for (unsigned long long i = 0; i < mlen; i++) {
			// every second bit is used for keystream, the others for MAC
			cc = 0;
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// transform it back to 8 bits per byte
					cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
					c_cnt++;
				}
				else {
					if (data.message[ac_cnt++] == 1) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
				}
			}
			C[i] = swapsbG(cc);
			*clen += 1;
		}

		// generate unused keystream bit
		next_zG(&grain, 0, 0);
		// the 1 in the padding means accumulation
		accumulateG(&grain);

		/* append MAC to ciphertext */
		unsigned long long acc_idx = 0;
		for (unsigned long long i = mlen; i < mlen + 8; i++) {
			unsigned char acc = 0;
			// transform back to 8 bits per byte
			for (int j = 0; j < 8; j++) {
				acc |= grain.auth_acc[8 * acc_idx + j] << (7 - j);
			}
			C[i] = swapsbG(acc);
			acc_idx++;
			*clen += 1;
		}

		free(data.message);
		free(m);
		free(ad);
	}
}

/// <summary>
/// //Transpose
__global__ void  grain_encrypt_ref_GPU_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * mp, uint64_t mlen,
	const uint8_t * adp, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npubp,
	const uint8_t * kp)
{
	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
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
		const uint8_t* M = const_cast<uint8_t*>(mp) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(adp) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npubp) + tno;
		const uint8_t* K = const_cast<uint8_t*>(kp) + tko;

		unsigned char* m = (unsigned char*)malloc(mlen);;
		unsigned char* ad = (unsigned char*)malloc(mlen);;
		unsigned char npub[12];
		unsigned char k[16];

		for (unsigned long long i = 0; i < mlen; i++) {
			m[i] = swapsbG(M[i]);
		}
		for (unsigned long long i = 0; i < adlen; i++) {
			ad[i] = swapsbG(A[i]);
		}
		for (unsigned long long i = 0; i < 12; i++) {
			npub[i] = swapsbG(N[i]);
		}
		for (unsigned long long i = 0; i < 16; i++) {
			k[i] = swapsbG(K[i]);
		}

		grain_state grain;
		grain_data data;

		init_grainG(&grain, k, npub);
		init_dataG(&data, m, mlen);
		*clen = 0;

		// authenticate adlen by prepeding to ad, using DER encoding
		unsigned char* ader;
		int aderlen = encode_derG(adlen, &ader);
		// append ad to buffer
		//ader = (unsigned char*)malloc(aderlen + adlen);
		memcpy(ader + aderlen, ad, adlen);

		unsigned long long ad_cnt = 0;
		unsigned char adval = 0;

		/* accumulate tag for associated data only */
		for (unsigned long long i = 0; i < aderlen + adlen; i++) {
			/* every second bit is used for keystream, the others for MAC */
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// do not encrypt
				}
				else {
					adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
					if (adval) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
					ad_cnt++;
				}
			}
		}

		free(ader);

		unsigned long long ac_cnt = 0;
		unsigned long long m_cnt = 0;
		unsigned long long c_cnt = 0;
		unsigned char cc = 0;

		// generate keystream for message
		for (unsigned long long i = 0; i < mlen; i++) {
			// every second bit is used for keystream, the others for MAC
			cc = 0;
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// transform it back to 8 bits per byte
					cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
					c_cnt++;
				}
				else {
					if (data.message[ac_cnt++] == 1) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
				}
			}
			C[i] = swapsbG(cc);
			*clen += 1;
		}

		// generate unused keystream bit
		next_zG(&grain, 0, 0);
		// the 1 in the padding means accumulation
		accumulateG(&grain);

		/* append MAC to ciphertext */
		unsigned long long acc_idx = 0;
		for (unsigned long long i = mlen; i < mlen + 8; i++) {
			unsigned char acc = 0;
			// transform back to 8 bits per byte
			for (int j = 0; j < 8; j++) {
				acc |= grain.auth_acc[8 * acc_idx + j] << (7 - j);
			}
			C[i] = swapsbG(acc);
			acc_idx++;
			*clen += 1;
		}

		free(data.message);
		free(m);
		free(ad);
	}
}

__global__ void grain_encrypt_MemOp_GPU_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * mp, uint64_t mlen,
	const uint8_t * adp, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npubp,
	const uint8_t * kp) {

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
		const uint8_t* M = const_cast<uint8_t*>(mp) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(adp) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npubp) + tno;
		const uint8_t* K = const_cast<uint8_t*>(kp) + tko;

		unsigned char* m = (unsigned char*)malloc(mlen);;
		unsigned char* ad = (unsigned char*)malloc(mlen);;
		unsigned char npub[12];
		unsigned char k[16];

		for (unsigned long long i = 0; i < mlen; i++) {
			m[i] = swapsbG(M[i]);
		}
		for (unsigned long long i = 0; i < adlen; i++) {
			ad[i] = swapsbG(A[i]);
		}
		for (unsigned long long i = 0; i < 12; i++) {
			npub[i] = swapsbG(N[i]);
		}
		for (unsigned long long i = 0; i < 16; i++) {
			k[i] = swapsbG(K[i]);
		}

		grain_state grain;
		grain_data data;

		init_grain_MemOp(&grain, k, npub);
		init_dataG(&data, m, mlen);
		*clen = 0;

		// authenticate adlen by prepeding to ad, using DER encoding
		unsigned char* ader;
		int aderlen = encode_derG(adlen, &ader);
		// append ad to buffer
		//ader = (unsigned char*)malloc(aderlen + adlen);
		memcpy(ader + aderlen, ad, adlen);

		unsigned long long ad_cnt = 0;
		unsigned char adval = 0;

		/* accumulate tag for associated data only */
		for (unsigned long long i = 0; i < aderlen + adlen; i++) {
			/* every second bit is used for keystream, the others for MAC */
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// do not encrypt
				}
				else {
					adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
					if (adval) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
					ad_cnt++;
				}
			}
		}

		free(ader);

		unsigned long long ac_cnt = 0;
		unsigned long long m_cnt = 0;
		unsigned long long c_cnt = 0;
		unsigned char cc = 0;

		// generate keystream for message
		for (unsigned long long i = 0; i < mlen; i++) {
			// every second bit is used for keystream, the others for MAC
			cc = 0;
			for (int j = 0; j < 16; j++) {
				unsigned char z_next = next_zG(&grain, 0, 0);
				if (j % 2 == 0) {
					// transform it back to 8 bits per byte
					cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
					c_cnt++;
				}
				else {
					if (data.message[ac_cnt++] == 1) {
						accumulateG(&grain);
					}
					auth_shiftG(grain.auth_sr, z_next);
				}
			}
			C[i] = swapsbG(cc);
			*clen += 1;
		}

		// generate unused keystream bit
		next_zG(&grain, 0, 0);
		// the 1 in the padding means accumulation
		accumulateG(&grain);

		/* append MAC to ciphertext */
		unsigned long long acc_idx = 0;
		for (unsigned long long i = mlen; i < mlen + 8; i++) {
			unsigned char acc = 0;
			// transform back to 8 bits per byte
			for (int j = 0; j < 8; j++) {
				acc |= grain.auth_acc[8 * acc_idx + j] << (7 - j);
			}
			C[i] = swapsbG(acc);
			acc_idx++;
			*clen += 1;
		}

		free(data.message);
		free(m);
		free(ad);
	}
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Grain_CAResult.csv", "w");
	fprintf(fpt, "Version, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	uint8_t* nonce, * key, * msg, * ad, * ct;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;

	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ct, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));

	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);

	printf("Version\t\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
#ifdef PRINT
		print('k', key + (i * CRYPTO_KEYBYTES), CRYPTO_KEYBYTES);
		printf(" ");
		print('n', nonce + (i * CRYPTO_NPUBBYTES), CRYPTO_NPUBBYTES);
		print('a', ad + (i * alen), alen);
		printf(" ");
		print('m', msg + (i * mlen), mlen);
		printf(" -> ");
#endif
		int result = crypto_aead_encrypt_ref(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
#ifdef PRINTC
		print('c', ct + (i * clen), clen);
#endif
	}
	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Host \tSerial\t\t%.6f\t%.6f\t\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));


	//GPU implementation
	LARGE_INTEGER frequencyT;
	LARGE_INTEGER TS, TE;
	double trans = 0;
	uint8_t* key_out, * msg_out, * ad_out, * nonce_out;

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

	uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c;
	uint64_t * d_clen;
	cudaEvent_t start, stop;

	cudaEventCreate(&start);
	cudaEventCreate(&stop);

	//Memory Allocation - Device
	cudaMallocHost((void**)& h_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
	cudaMalloc((void**)& d_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
	cudaMalloc((void**)& d_n, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
	cudaMalloc((void**)& d_k, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
	cudaMalloc((void**)& d_m, BATCH * (uint64_t)mlen * sizeof(uint8_t));				//Message
	cudaMalloc((void**)& d_a, BATCH * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
	cudaMallocHost((void**)& d_clen, sizeof(uint64_t));

	//Memory initialisation
	cudaMemset(d_n, 0, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMemset(d_k, 0, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMemset(d_m, 0, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMemset(d_a, 0, BATCH * (uint64_t)alen * sizeof(uint8_t));
	memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

	//Parallel Granularity
	for (int i = 64; i < 1025; i *= 2) {
		float memcpy_h2d, elapsed, memcpy_d2h, total;

		//1 = Ref, 2 = MemOp, 3 = Ref Trans , 4 = MemOp Trans
		for (int z = 1; z < 5; z++) {

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
			else if (z == 3) { // for coleasced
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
			dim3 blocks(ceil((double)BATCH / (double)i));		
			if (z > 2) {
				threads.y = i;
				double temp = (double)BATCH / ((double)threads.x * (double)threads.y);
				blocks.x = (temp < 1) ? 1 : ceil(temp); // at least 1 block
			}

			kernel = ((z == 1) ? &grain_encrypt_ref_GPU : ((z == 2) ? &grain_encrypt_MemOp_GPU
				: ((z == 3) ? &grain_encrypt_ref_GPU_Trans : grain_encrypt_MemOp_GPU_Trans)));

			char* kernelName = ((z == 1) ? "GPU Ref " : ((z == 2) ? "Mem Op" : ((z == 3) ? "GPU Ref Trans " : "MemOp Trans ")));

			//Kernel execution
			cudaEventRecord(start, 0);
			kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			elapsed = 0.0f;
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);
			memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			
			double Ttime = 0;
			if (z < 3)
				total = memcpy_h2d + elapsed + memcpy_d2h;
			else {
				total = memcpy_h2d + trans + elapsed + memcpy_d2h;
				Ttime = trans;
			}

			printf("%s\t %u \t\t%.6f\t%.6f \t%.6f  \t%.f \t%.f\n", kernelName, threads.x, memcpy_h2d,
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

	//Device memory
	cudaFree(d_n);
	cudaFree(d_k);
	cudaFree(d_a);
	cudaFree(d_m);
	cudaFree(d_clen);
	cudaFree(h_c);
	cudaFree(d_c);
	cudaEventDestroy(start);
	cudaEventDestroy(stop);
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();
}