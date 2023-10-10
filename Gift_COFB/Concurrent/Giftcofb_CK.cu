
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "operations.h"
#include "params.h"
#include "giftcofb.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	*clen = mlen + CRYPTO_ABYTES;

	unsigned char* M = const_cast<unsigned char*>(m);
	unsigned char* A = const_cast<unsigned char*>(ad);
	unsigned char* N = const_cast<unsigned char*>(npub);
	unsigned char* K = const_cast<unsigned char*>(k);
	unsigned char* C = const_cast<unsigned char*>(c);

	unsigned i;
	unsigned emptyA, emptyM;

	if (!COFB_ENCRYPT) {
		mlen -= CRYPTO_ABYTES;
	}

	emptyA = (adlen == 0) ? 1 : 0;
	emptyM = (mlen == 0) ? 1 : 0;

	/*Mask-Gen*/
	block Y, input;
	half_block offset;
	/*nonce is 128-bit*/
	for (i = 0; i < 16; i++)
		input[i] = N[i];

	giftb128(input, k, Y);
	for (i = 0; i < 8; i++)
		offset[i] = Y[i];


	/*Process AD*/
	/*non-empty A*/
/*full blocks*/
	while (adlen > 16) {
		/* X[i] = (A[i] + G(Y[i-1])) + offset */
		pho1(input, Y, A, 16);
		/* offset = 2*offset */
		double_half_block(offset, offset);
		xor_topbar_block(input, input, offset);
		/* Y[i] = E(X[i]) */
		giftb128(input, K, Y);

		A = A + 16;
		adlen -= 16;
	}

	/* last block */
	/* full block: offset = 3*offset */
	/* partial block: offset = 3^2*offset */
	triple_half_block(offset, offset);
	if ((adlen % 16 != 0) || (emptyA)) {
		triple_half_block(offset, offset);
	}

	if (emptyM) {
		/* empty M: offset = 3^2*offset */
		triple_half_block(offset, offset);
		triple_half_block(offset, offset);
	}

	/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
	pho1(input, Y, A, adlen);

	xor_topbar_block(input, input, offset);
	/* Y[a] = E(X[a]) */
	giftb128(input, K, Y);


	/* Process M */
	/* full blocks */
	while (mlen > 16) {
		double_half_block(offset, offset);
		/* C[i] = Y[i+a-1] + M[i]*/
		/* X[i] = M[i] + G(Y[i+a-1]) + offset */
		if (COFB_ENCRYPT) {
			pho(Y, M, input, C, 16);
		}
		else {
			phoprime(Y, M, input, C, 16);
		}

		xor_topbar_block(input, input, offset);
		/* Y[i] = E(X[i+a]) */
		giftb128(input, K, Y);

		M = M + 16;
		C = C + 16;
		mlen -= 16;
	}

	if (!emptyM) {
		/* full block: offset = 3*offset */
		/* empty data / partial block: offset = 3^2*offset */
		triple_half_block(offset, offset);
		if (mlen % 16 != 0) {
			triple_half_block(offset, offset);
		}
		/* last block */
		/* C[m] = Y[m+a-1] + M[m]*/
		/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
		if (COFB_ENCRYPT) {
			pho(Y, M, input, C, mlen);
			C += mlen;
		}
		else {
			phoprime(Y, M, input, C, mlen);
			M += mlen;
		}


		xor_topbar_block(input, input, offset);
		/* T = E(X[m+a]) */
		giftb128(input, K, Y);
	}

	memcpy(C, Y, CRYPTO_ABYTES);

	return 0;
}

__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
{
	*clen = mlen + CRYPTO_ABYTES;
	int tid = threadIdx.x, bid = blockIdx.x;

	if ((bid * blockDim.x + tid) < BATCH) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (*clen) + tid * (*clen);	//instead of crypto_abytes

		unsigned char* M = const_cast<unsigned char*>(m + offset_msg);
		unsigned char* A = const_cast<unsigned char*>(ad + offset_ad);
		unsigned char* N = const_cast<unsigned char*>(npub + offset_nonce);
		unsigned char* K = const_cast<unsigned char*>(k + offset_key);
		unsigned char* C = const_cast<unsigned char*>(c + offset_ct);

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	*clen = mlen + CRYPTO_ABYTES;

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		//temporarily buffer
		uint8_t* kout = const_cast<unsigned char*>(k + blockIdx.x * blockDim.x);
		uint8_t * nout = const_cast<unsigned char*>(npub + blockIdx.x * blockDim.x);
		uint8_t * mout = const_cast<unsigned char*>(m + blockIdx.x * blockDim.x);
		uint8_t * aout = const_cast<unsigned char*>(ad + blockIdx.x * blockDim.x);

		kout[tko] = k[tki]; // transpose from row to col for key
		nout[tko] = npub[tki]; //for nonce
		mout[tmo] = m[tmi]; //for message
		aout[tao] = ad[tai]; //for additional data

		__syncthreads();

		uint8_t * C = c + tci;
		uint8_t * M = mout + tmo;
		uint8_t * A = aout + tao;
		uint8_t * N = nout + tko;
		uint8_t * K = kout + tko;

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__inline__ __device__ void encrypt_unroll4(uint8_t* c, uint64_t* clen, uint8_t* m, uint64_t mlen, uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, uint8_t* npub, uint8_t* k, uint32_t tko, uint32_t tao, uint32_t tmo, uint32_t tci) {

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {
		uint8_t* C = c + tci;
		uint8_t* M = m + tmo;
		uint8_t* A = ad + tao;
		uint8_t* N = npub + tko;
		uint8_t* K = k + tko;

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	*clen = mlen + CRYPTO_ABYTES;

	/* Determine matrix index for each data*/
	uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
	uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
	uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
	uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
	uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
	uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
	uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

	//read in col , write in row
	uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
	uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
	uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
	uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
	uint32_t tai = taiy * adlen + taix; // access in columns - ad 
	uint32_t tao = taix * adlen + taiy; // access in columns - ad 
	uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

	//temporarily buffer
	uint8_t* kout = const_cast<uint8_t*>(k) + blockIdx.x * blockDim.x;
	uint8_t* nout = const_cast<uint8_t*>(npub) + blockIdx.x * blockDim.x;
	uint8_t* mout = const_cast<uint8_t*>(m) + blockIdx.x * blockDim.x;
	uint8_t* aout = const_cast<uint8_t*>(ad) + blockIdx.x * blockDim.x;

	kout[tko] = k[tki];													kout[tko + blockDim.x] = k[tki + blockDim.x];
	kout[tko + 2 * blockDim.x] = k[tki + 2 * blockDim.x];				kout[tko + 3 * blockDim.x] = k[tki + 3 * blockDim.x];

	nout[tko] = npub[tki];												nout[tko + blockDim.x] = npub[tki + blockDim.x];
	nout[tko + 2 * blockDim.x] = npub[tki + 2 * blockDim.x];			nout[tko + 3 * blockDim.x] = npub[tki + 3 * blockDim.x];

	mout[tmo] = m[tmi];													mout[tmo + blockDim.x] = m[tmi + blockDim.x];
	mout[tmo + 2 * blockDim.x] = m[tmi + 2 * blockDim.x];				mout[tmo + 3 * blockDim.x] = m[tmi + 3 * blockDim.x];

	aout[tao] = ad[tai];												aout[tao + blockDim.x] = ad[tai + blockDim.x];
	aout[tao + 2 * blockDim.x] = ad[tai + 2 * blockDim.x];				aout[tao + 3 * blockDim.x] = ad[tai + 3 * blockDim.x];

	__syncthreads();

	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko, tao, tmo, tci);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + blockDim.x, tao + blockDim.x, tmo + blockDim.x, tci + blockDim.x);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + 2 * blockDim.x, tao + 2 * blockDim.x, tmo + 2 * blockDim.x, tci + 2 * blockDim.x);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + 3 * blockDim.x, tao + 3 * blockDim.x, tmo + 3 * blockDim.x, tci + 3 * blockDim.x);

}

int main()
{
	FILE* fpt;
	fpt = fopen("Giftcofb_Concurent_raw.csv", "w");
	fprintf(fpt, "Version, Kernel, Dimension, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Memcpy D2H, Speed UP (Execution), AEAD\s, Throughput (Times)\n");

	printf("\nSize Implementation : %d\n", BATCH);

	uint8_t* nonce, * key, * msg, * ad, * ct, * msg2;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen = MAX_CIPHER_LENGTH;	// cipher length
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

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}

	QueryPerformanceCounter(&t2);
	cpu_t = ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	//Print Time
	printf("Version\t\tCKernel\tConfiguration\t\t\tMemcpyH2D\tMemcpyD2H\tKernel Time \t\t\tTotal\t\t\tAEAD/s\n\n");
	printf("Host\t\t-\t\t-\t\t\t%.6f\t%.6f\t%.6f \t( %.2f )\t%.6f  ( %.2f )\t%.f\n", 0.0, 0.0, cpu_t, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000));
	fprintf(fpt, "%s, %d, %d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0, 0, ((BATCH * clen * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, 0.0, BATCH / (cpu_t / 1000), 0.0);


	//GPU implementation
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
	memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_n, 0, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMemset(d_k, 0, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMemset(d_m, 0, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMemset(d_a, 0, BATCH * (uint64_t)alen * sizeof(uint8_t));

	//Warm Up Kernel
	cudaEventRecord(start, 0);
	crypto_aead_encrypt_gpu_global << <BATCH / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
	cudaEventRecord(stop, 0);
	cudaEventSynchronize(stop);
	float warmup;
	cudaEventElapsedTime(&warmup, start, stop);

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

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
			float memcpy_h2d;
			cudaEventElapsedTime(&memcpy_h2d, start, stop);

			for (int i = 1; i < 513; i *= 2) {

				if (i >= 64) {
					float elapsed, memcpy_d2h, total;

					for (int a = 1; a <= 3; a++) {

						//Configuration.
						dim3 threads(i);
						double temp = (double)iBATCH / (double)i;
						dim3 blocks(ceil(temp));		//for unoptimised

						if (a > 1) {
							threads.y = i;
							temp = (double)iBATCH / ((double)threads.x * (double)threads.y);
							blocks.x = ceil(temp);
							blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
						}

						kernel = ((a == 1) ? &crypto_aead_encrypt_gpu_global : ((a == 2) ? &crypto_aead_encrypt_gpu_rcwr_GpuTranspose : &crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4));
						char* kernelName = ((a == 1) ? "GPU Unoptimised" : ((a == 2) ? "GPU Tran" : "GPU TransU4"));

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
						cudaEventElapsedTime(&elapsed, start, stop);

						//Memory Copy from D2H
						cudaEventRecord(start, 0);
						for (int i = 0; i < z; ++i) {
							int ioffset = i * iBATCH;
							cudaMemcpyAsync(&h_c[ioffset * MAX_CIPHER_LENGTH], &d_c[ioffset * MAX_CIPHER_LENGTH], iCsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
						}
						cudaEventRecord(stop, 0);
						cudaEventSynchronize(stop);
						cudaEventElapsedTime(&memcpy_d2h, start, stop);

						checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);

						total = memcpy_h2d + elapsed + memcpy_d2h;
						printf("%s\t%d\t<<< (%u), (%u,%u)>>>\t\t%.6f\t%.6f\t%.6f    ( %.2f )\t\t%.6f  ( %.2f )\t%.f\t%.2f\n", kernelName, z, blocks.x, threads.x, threads.y, memcpy_h2d,
							memcpy_d2h, elapsed, cpu_t / elapsed, total, cpu_t / total, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_t / 1000)));

						fprintf(fpt, "%s, %d, (%u)(%u %u), %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.f,%.2f\n", kernelName, z, blocks.x, threads.x, threads.y, (size * 2e-6) / total, total,
							cpu_t / total, (size * 2e-6) / total * 8, memcpy_h2d, elapsed, memcpy_d2h, cpu_t / elapsed, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_t / 1000)));
					}
					printf("\n");

				}
			} 
			printf("\n======================================================================================================================================================\n");
			for (int i = 0; i < z; i++)
				cudaStreamDestroy(GPUstreams[i]);
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
	fclose(fpt);
	cudaDeviceReset();

	return 0;
}