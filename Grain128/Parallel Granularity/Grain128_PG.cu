
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
	const uint8_t * kp, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
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
	const uint8_t * kp, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
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

__global__ void grain_encrypt_FineOp_GPU(
	uint8_t * c, uint64_t * clen,
	const uint8_t * mp, uint64_t mlen,
	const uint8_t * adp, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npubp,
	const uint8_t * kp, int Batch) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < Batch) {
		uint32_t offset_msg = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + (tid / fineLevel) * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES); //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+((tid / fineLevel) * (MAX_CIPHER_LENGTH));	//instead of crypto_abytes

		uint8_t * C = c + offset_ct;
		uint8_t * M = const_cast<uint8_t*>(mp) + offset_msg;
		uint8_t * A = const_cast<uint8_t*>(adp) + offset_ad;
		uint8_t * N = const_cast<uint8_t*>(npubp) + offset_nonce;
		uint8_t * K = const_cast<uint8_t*>(kp) + offset_key;

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

		init_grain_Fine(&grain, k, npub);
		init_data_Fine(&data, m, mlen);
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
				unsigned char z_next = next_zG_Fine(&grain, 0, 0);
				if (j % 2 == 0) {
					// do not encrypt
				}
				else {
					adval = ader[ad_cnt / 8] & (1 << (7 - (ad_cnt % 8)));
					if (adval) {
						accumulateG_Fine(&grain);
					}
					auth_shiftG_Fine(grain.auth_sr, z_next);
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
				unsigned char z_next = next_zG_Fine(&grain, 0, 0);
				if (j % 2 == 0) {
					// transform it back to 8 bits per byte
					cc |= (data.message[m_cnt++] ^ z_next) << (7 - (c_cnt % 8));
					c_cnt++;
				}
				else {
					if (data.message[ac_cnt++] == 1) {
						accumulateG_Fine(&grain);
					}
					auth_shiftG_Fine(grain.auth_sr, z_next);
				}
			}
			C[i] = swapsbG(cc);
			*clen += 1;
		}

		// generate unused keystream bit
		next_zG_Fine(&grain, 0, 0);
		// the 1 in the padding means accumulation
		accumulateG_Fine(&grain);

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
	char writeFile[100];
	char fineLvl[1];
	strcpy(writeFile, "Grain_PGResult_F");
	sprintf(fineLvl, "%d", fineLevel);
	strcat(writeFile, fineLvl);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	int BATCH[BATCH_SIZE] = { 64000, 256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ct;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		//Print Host Time
		printf("\nVersion \tLatency (ms)\t\tAEAD/s\n");

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
			int result = crypto_aead_encrypt_ref(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
#ifdef PRINTC
			print('c', ct + (i * clen), clen);
#endif
		}
		QueryPerformanceCounter(&t2);
		cpu_t = 0;
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host Ref", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("%s:\t\t\t\t\t%.f\n", "Host Ref", BATCH[z] / (cpu_t / 1000));
		//GPU implementation
		uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c;
		uint64_t * d_clen;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)& h_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMalloc((void**)& d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_n, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
		cudaMalloc((void**)& d_k, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
		cudaMalloc((void**)& d_m, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));				//Message
		cudaMalloc((void**)& d_a, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
		cudaMallocHost((void**)& d_clen, sizeof(uint64_t));

		//Memory initialisation
		memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_n, 0, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMemset(d_k, 0, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMemset(d_m, 0, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));
		cudaMemset(d_a, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));

		//Warm Up 
		grain_encrypt_ref_GPU << <BATCH[z] / 1024, 1024 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		grain_encrypt_MemOp_GPU << <BATCH[z] / 1024, 1024 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);

		//Memory Copy from H2D
		cudaEventRecord(start, 0);
		cudaMemcpy(d_n, nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_k, key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_m, msg, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_a, ad, BATCH[z] * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float memcyp_h2d = 0;
		cudaEventElapsedTime(&memcyp_h2d, start, stop);
		printf("\nMemcpy H2D :\t %.6f ms\t(%f GB/s)\n\n", memcyp_h2d, ((BATCH[z] * mlen * sizeof(uint8_t)) * 1e-6) / memcyp_h2d);

		//Parallel Granularity
		for (int i = 1; i < 1025; i *= 2) {

			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);

			//Mem Op
			cudaEventRecord(start, 0);
			grain_encrypt_MemOp_GPU << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float elapsed = 0;
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_d2h = 0;
			*d_clen = MAX_CIPHER_LENGTH;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("Parallel Granularity", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);
#ifdef WRITEFILE
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, elapsed, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU MemOp");
#else
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, elapsed, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU MemOp");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Ref
			cudaEventRecord(start, 0);
			grain_encrypt_ref_GPU << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			elapsed, memcpy_d2h = 0;
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			*d_clen = MAX_CIPHER_LENGTH;

			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("Parallel Granularity", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, elapsed, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU Ref");
#else
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, elapsed, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU Ref");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

			//For fine grain
			if (i == fineLevel) {
				size_t size = BATCH[z] * (*d_clen) * sizeof(uint8_t);
				dim3 threads(Tlimit); //fine grain each block max 512 threads to divide by 4/8/16 threads for fine grain.
				double temp = ((double)BATCH[z] / (Tlimit / (double)fineLevel));
				dim3 blocks2(ceil(temp));		//for unoptimised

				cudaEventRecord(start, 0);
				grain_encrypt_FineOp_GPU << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				float elapsed = 0;
				cudaEventElapsedTime(&elapsed, start, stop);

				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				float memcpy_d2h = 0;
				*d_clen = MAX_CIPHER_LENGTH;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult("Parallel Granularity", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

				memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

				float total = memcyp_h2d + elapsed + memcpy_d2h;
				printf("Fine %d :\t %.6f ms\t\t%.f\n", fineLevel, total, BATCH[z] / (total / 1000));
#ifdef WRITEFILE
				fprintf(fpt, "T%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f, %s%d\n", i, BATCH[z], (size * 2e-6) / total, total, (cpu_t / total), ((size * 2e-6) / total) * 8, memcyp_h2d, elapsed, (cpu_t / elapsed), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_t / 1000)), "Fine ", fineLevel);
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

		//Device memory
		cudaFree(d_n);
		cudaFree(d_k);
		cudaFree(d_a);
		cudaFree(d_m);
		cudaFree(d_c);
		cudaFree(h_c);
		cudaFree(d_clen);

		cudaEventDestroy(start);
		cudaEventDestroy(stop);
		printf("-----------------------------------------------------------------------------------------------------\n");

#ifdef WRITEFILE
		fclose(fpt);
#endif
	
	}
	cudaDeviceReset();
	return 0;
}
