﻿#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include "params.h"
#include "encrypt.c"
#include "photon.c"
#include "operations.h"


static int crypto_aead_encrypt(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k, int mode)
{
	uint8_t* C = c;
	uint8_t* T = c + mlen;
	const uint8_t* M = m;
	const uint8_t* A = ad;
	const uint8_t* N = npub;
	const uint8_t* K = k;

	uint8_t State[STATE_INBYTES] = { 0 };
	uint8_t c0;
	uint8_t c1;

	(void)nsec;

	concatenate(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

	if ((adlen == 0) && (mlen == 0))
	{
		XOR_const(State, 1);
		TAG(T, State, mode);
		*clen = TAG_INBYTES;
		return 0;
	}

	c0 = selectConst((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
	c1 = selectConst((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

	if (adlen != 0) HASH(State, A, adlen, c0, mode);
	if (mlen != 0) ENCorDEC(State, C, M, mlen, c1, ENC, mode);

	TAG(T, State, mode);
	*clen = mlen + TAG_INBYTES;
	return 0;
}

__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k, int mode)
{
	int i, tid = threadIdx.x, bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen + i;
	uint32_t idx_ia = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * (*clen) + tid * (*clen);

	uint8_t* C = c + idx_out;
	uint8_t* T = c + mlen + idx_out;
	const uint8_t* M = m + idx_im;
	const uint8_t* A = ad + idx_ia;
	const uint8_t* N = npub + idx_nk;
	const uint8_t* K = k + idx_nk;

	uint8_t State[STATE_INBYTES] = { 0 };
	//__shared__ uint8_t State[STATE_INBYTES];
	uint8_t c0;
	uint8_t c1;

	(void)nsec;

	concatenateG(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

	if ((adlen == 0) && (mlen == 0))
	{
		XOR_constG(State, 1);
		TAGG(T, State, mode);
		*clen = TAG_INBYTES;
	}

	c0 = selectConstG((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
	c1 = selectConstG((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

	if (adlen != 0) HASHG(State, A, adlen, c0, mode);
	if (mlen != 0) ENCorDECG(State, C, M, mlen, c1, ENC, mode);

	TAGG(T, State, mode);
	*clen = mlen + TAG_INBYTES;
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k, int mode)
{
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

	kout[tko] = k[tki]; // transpose from row to col for key
	nout[tko] = npub[tki]; //for nonce
	mout[tmo] = m[tmi]; //for message
	aout[tao] = ad[tai]; //for additional data

	__syncthreads();
	k = kout;		npub = nout;		m = mout;		ad = aout;

	uint8_t* C = c + tci;
	uint8_t* T = c + mlen + tci;
	const uint8_t* M = m + tmo;
	const uint8_t* A = ad + tao;
	const uint8_t* N = npub + tko;
	const uint8_t* K = k + tko;

	uint8_t State[STATE_INBYTES] = { 0 };
	uint8_t c0;
	uint8_t c1;

	(void)nsec;

	concatenateG(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

	if ((adlen == 0) && (mlen == 0))
	{
		XOR_constG(State, 1);
		TAGG(T, State, mode);
		*clen = TAG_INBYTES;
	}

	c0 = selectConstG((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
	c1 = selectConstG((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

	if (adlen != 0) HASHG(State, A, adlen, c0, mode);
	if (mlen != 0) ENCorDECG(State, C, M, mlen, c1, ENC, mode);

	TAGG(T, State, mode);
	*clen = mlen + TAG_INBYTES;
}

//GPU GlobalMem - transpose Col in Host & Unroll 4
__inline__ __device__ void encrypt_unroll4(uint8_t * c, uint64_t * clen, const uint8_t * m, uint64_t mlen, const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k, int mode) {

	uint8_t* C = c;
	uint8_t* T = c + mlen;
	const uint8_t* M = m;
	const uint8_t* A = ad;
	const uint8_t* N = npub;
	const uint8_t* K = k;

	uint8_t State[STATE_INBYTES] = { 0 };
	uint8_t c0;
	uint8_t c1;

	(void)nsec;

	concatenateG(State, N, NOUNCE_INBYTES, K, KEY_INBYTES);

	if ((adlen == 0) && (mlen == 0))
	{
		XOR_constG(State, 1);
		TAGG(T, State, mode);
		*clen = TAG_INBYTES;
	}

	c0 = selectConstG((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
	c1 = selectConstG((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

	if (adlen != 0) HASHG(State, A, adlen, c0, mode);
	if (mlen != 0) ENCorDECG(State, C, M, mlen, c1, ENC, mode);

	TAGG(T, State, mode);
	*clen = mlen + TAG_INBYTES;
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4(uint8_t * c, uint64_t * clen, const uint8_t * m, uint64_t mlen, const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k, int mode) {

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

	encrypt_unroll4(c + tci, clen, mout + tmo, mlen, aout + tao, adlen, nsec, nout + tko, kout + tko, mode);
	encrypt_unroll4(c + (tci + blockDim.x), clen, mout + (tmo + blockDim.x), mlen, aout + (tao + blockDim.x), adlen, nsec, nout + (tko + blockDim.x), kout + (tko + blockDim.x), mode);
	encrypt_unroll4(c + (tci + 2 * blockDim.x), clen, mout + (tmo + 2 * blockDim.x), mlen, aout + (tao + 2 * blockDim.x), adlen, nsec, nout + (tko + 2 * blockDim.x), kout + (tko + 2 * blockDim.x), mode);
	encrypt_unroll4(c + (tci + 3 * blockDim.x), clen, mout + (tmo + 3 * blockDim.x), mlen, aout + (tao + 3 * blockDim.x), adlen, nsec, nout + (tko + 3 * blockDim.x), kout + (tko + 3 * blockDim.x), mode);
}

int main()
{
#ifdef WRITEFILE
	//FILE writing
	FILE* fpt;
	fpt = fopen("Photon_Coleasced.csv", "w");
	fprintf(fpt, "Version, Dimension, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, Speed UP (Execution), AEAD/s, Throughput (Times)\n");
#endif

	printf("\nSize Implementation : %d\n", BATCH);

	//Host variable
	uint8_t* nonce, * key, * msg, * ad, * ct, * ct2;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;

	//Memory Allocation - HOST
	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ct, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMallocHost((void**)& ct2, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));

	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);
	BuildTableSCShRMCS();

	//Host - no precomputed
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), 0); // 0 is no table
	}
	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	//Print Host Time
	printf("Version\t\t\t\tConfiguration\t\t\tMemcpyH2D\tMemcpyD2H\tKernel Time\t\t        Total\t\t\t\tAEAD/s\n\n");

#ifdef WRITEFILE
	fprintf(fpt, "%s %s, %d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", "Noprecomputed", 0, ((BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, 0.0, cpu_t, 0.0, 0.0, BATCH / (cpu_t / 1000), 0.0);
#endif

	printf("Host No-precomp\t\t\tSerial\t\t\t\t%.6f\t%.6f\t%.6f\t\t%.6f \t%.f\n", 0.0, 0.0, cpu_t, cpu_t, BATCH / (cpu_t / 1000));

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt(OFFSET(ct2, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), 1); //1 is have table
	}
	QueryPerformanceCounter(&t2);
	cpu_t = 0;
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	checkResult("H", ct, ct2, MAX_CIPHER_LENGTH, BATCH);

#ifdef WRITEFILE
	fprintf(fpt, "%s %s, %d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", "precomputed", 0, ((BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, 0.0, cpu_t, 0.0, 0.0, BATCH / (cpu_t / 1000), 0.0);
#endif

	printf("Host Precomp\t\t\tSerial\t\t\t\t%.6f\t%.6f\t%.6f\t\t%.6f\t%.f\n", 0.0, 0.0, cpu_t, cpu_t, BATCH / (cpu_t / 1000));

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

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*, int);
	size_t size = BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t);

	for (int i = 1; i < 1025; i *= 2) {
		if (i >= 64) {

			float memcpy_h2d, elapsed, memcpy_d2h, total;

			for (int z = 1; z < 4; z++) {	//1 is non-coalesced

				if (z == 1) { // for normal
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
				else if (z == 2) { // for coleasced
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
				dim3 blocks(BATCH / i);

				if (z > 1) {	// if optimised have 2D
					threads.y = i;
					int temp = BATCH / (threads.x * threads.y);	// blocks calculate for 2D threads.
					blocks.x = (z == 3) ? temp / 4 : temp; // at least 1 block, if unroll then div 4
					blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
				}

				kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global : ((z == 2) ? &crypto_aead_encrypt_gpu_rcwr_GpuTranspose : &crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4));
				char* kernelName = ((z == 1) ? "GPU Unoptimised" : ((z == 2) ? "GPU Tran" : "GPU TransU4"));

				for (int q = 1; q <= 4; q++) {

					char* modeName = ((q == 1) ? "No-Precom" : ((q == 2) ? "Pre-comp" : ((q == 3) ? "Shared Mem" : "Warp Shuffle")));

					//Kernel execution
					memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
					cudaEventRecord(start);
					kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k, q);
					cudaEventRecord(stop);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&elapsed, start, stop);

					//Memory Copy from D2H
					cudaEventRecord(start, 0);
					cudaMemcpy(h_c, d_c, BATCH * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&memcpy_d2h, start, stop);
					checkResult(modeName, ct, h_c, MAX_CIPHER_LENGTH, BATCH);

					double Ttime = 0;
					if (z < 2)
						total = memcpy_h2d + elapsed + memcpy_d2h;
					else {
						total = memcpy_h2d + trans + elapsed + memcpy_d2h;
						Ttime = trans;
					}

					printf("%s %s\t\t%u\t\t\t%.6f\t%.6f\t%.6f \t%.6f \t%.f   \t%.2f\n", kernelName, modeName, threads.x, memcpy_h2d,
						memcpy_d2h, elapsed, total, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_t / 1000)));

#ifdef WRITEFILE
					fprintf(fpt, "%s %s, %u, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", kernelName, modeName, threads.x, (size * 2e-6) / total, total,
						cpu_t / total, (size * 2e-6) / total * 8, memcpy_h2d, Ttime, elapsed, memcpy_d2h, cpu_t / elapsed, BATCH / (total / 1000), (BATCH / (total / 1000)) / (BATCH / (cpu_t / 1000)));
#endif

				}

			}

			printf("\n======================================================================================================================================================\n");

		}
	}

	//Free Memory
	//Host memory
	cudaFree(nonce);
	cudaFree(key);
	cudaFree(msg);
	cudaFree(ad);
	cudaFree(ct);
	cudaFree(ct2);

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

#ifdef WRITEFILE
	fclose(fpt);
#endif

	cudaDeviceReset();
	return 0;
}
