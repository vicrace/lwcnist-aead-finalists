#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <math.h>
#include "xoodyakCPU.h"
#include "xoodyakGPU.h"
#include "params.h"
#include "operations.h"


int crypto_aead_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k)
{
	Xoodyak_Instance    instance;

	(void)nsec;

	Xoodyak_Initialize(&instance, k, CRYPTO_KEYBYTES, npub, CRYPTO_NPUBBYTES, NULL, 0);
	Xoodyak_Absorb(&instance, ad, (size_t)adlen);
	Xoodyak_Encrypt(&instance, m, c, (size_t)mlen);
	Xoodyak_Squeeze(&instance, c + mlen, CRYPTO_ABYTES);
	*clen = mlen + CRYPTO_ABYTES;

	return 0;
}

__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k)
{
	Xoodyak_Instance    instance;

	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;

	if ((bid * blockDim.x + tid) < BATCH) {
		uint8_t* C = c + (bid * blockDim.x * (*clen) + tid * (*clen));
		uint8_t * T = c + mlen + (bid * blockDim.x * (*clen) + tid * (*clen));
		const uint8_t * M = m + (bid * blockDim.x * mlen + (tid * mlen));
		const uint8_t * A = ad + (bid * blockDim.x * adlen + tid * adlen);
		const uint8_t * N = npub + (bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES);
		const uint8_t * K = k + (bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES);

		Xoodyak_InitializeG(&instance, K, CRYPTO_KEYBYTES, N, CRYPTO_NPUBBYTES, NULL, 0);
		Xoodyak_AbsorbG(&instance, A, (size_t)adlen);
		Xoodyak_EncryptG(&instance, M, C, (size_t)mlen);
		Xoodyak_SqueezeAnyG(&instance, C + mlen, CRYPTO_ABYTES, 0x40);
		*clen = mlen + CRYPTO_ABYTES;
	}

}

__global__ void crypto_aead_encrypt_gpu_global_Op(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k)
{
	Xoodyak_Instance    instance;

	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;
	uint8_t* C = c + (bid * blockDim.x * (*clen) + tid * (*clen));
	uint8_t * T = c + mlen + (bid * blockDim.x * (*clen) + tid * (*clen));
	const uint8_t * M = m + (bid * blockDim.x * mlen + (tid * mlen));
	const uint8_t * A = ad + (bid * blockDim.x * adlen + tid * adlen);
	const uint8_t * N = npub + (bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES);
	const uint8_t * K = k + (bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES);

	Xoodyak_InitializeG_Op(&instance, K, CRYPTO_KEYBYTES, N, CRYPTO_NPUBBYTES, NULL, 0);
	Xoodyak_AbsorbG_Op(&instance, A, (size_t)adlen);
	Xoodyak_EncryptG_Op(&instance, M, C, (size_t)mlen);
	Xoodyak_SqueezeAnyG_Op(&instance, C + mlen, CRYPTO_ABYTES, 0x40);
	*clen = mlen + CRYPTO_ABYTES;

}


__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k) {

	/* Determine matrix index for each data*/
	uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
	uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
	uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
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
	const uint8_t* N = const_cast<uint8_t*>(npub) + tko;
	const uint8_t* K = const_cast<uint8_t*>(k) + tko;

	Xoodyak_Instance    instance;

	(void)nsec;

	Xoodyak_InitializeG(&instance, K, CRYPTO_KEYBYTES, N, CRYPTO_NPUBBYTES, NULL, 0);
	Xoodyak_AbsorbG(&instance, A, (size_t)adlen);
	Xoodyak_EncryptG(&instance, M, C, (size_t)mlen);
	Xoodyak_SqueezeAnyG(&instance, C + mlen, CRYPTO_ABYTES, 0x40);
	*clen = mlen + CRYPTO_ABYTES;
}


__inline__ __device__ void encrypt_unroll4(uint8_t * c, uint64_t * clen, const uint8_t * m, uint64_t mlen, const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k, uint32_t tko, uint32_t tao, uint32_t tmo, uint32_t tci) {

	Xoodyak_Instance    instance;
	(void)nsec;

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {
		Xoodyak_InitializeG(&instance, k + tko, CRYPTO_KEYBYTES, npub + tko, CRYPTO_NPUBBYTES, NULL, 0);
		Xoodyak_AbsorbG(&instance, ad + tao, (size_t)adlen);
		Xoodyak_EncryptG(&instance, m + tmo, c + tci, (size_t)mlen);
		Xoodyak_SqueezeAnyG(&instance, (c + tci) + mlen, CRYPTO_ABYTES, 0x40);
		*clen = mlen + CRYPTO_ABYTES;
	}
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k) {

	/* Determine matrix index for each data*/
	uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
	uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
	uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
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


	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko, tao, tmo, tci);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + blockDim.x, tao + blockDim.x, tmo + blockDim.x, tci + blockDim.x);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + 2 * blockDim.x, tao + 2 * blockDim.x, tmo + 2 * blockDim.x, tci + 2 * blockDim.x);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + 3 * blockDim.x, tao + 3 * blockDim.x, tmo + 3 * blockDim.x, tci + 3 * blockDim.x);

}

__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose_Op(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k)
{
	/* Determine matrix index for each data*/
	uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
	uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
	uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
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
	const uint8_t* N = const_cast<uint8_t*>(npub) + tko;
	const uint8_t* K = const_cast<uint8_t*>(k) + tko;

	Xoodyak_Instance    instance;

	Xoodyak_InitializeG_Op(&instance, K, CRYPTO_KEYBYTES, N, CRYPTO_NPUBBYTES, NULL, 0);
	Xoodyak_AbsorbG_Op(&instance, A, (size_t)adlen);
	Xoodyak_EncryptG_Op(&instance, M, C, (size_t)mlen);
	Xoodyak_SqueezeAnyG_Op(&instance, C + mlen, CRYPTO_ABYTES, 0x40);
	*clen = mlen + CRYPTO_ABYTES;
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Xoodyak_CAResult.csv", "w");
	fprintf(fpt, "Version, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	uint8_t* nonce, * key, * msg, * ad, * ct, * msg2;
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

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);

	for (int i = 0; i < BATCH; i++) {
		int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}

	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Version\t\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");
	printf("Host \t\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t\t\t%.f\n", 0.0, 0.0,cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));


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
	memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_n, 0, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMemset(d_k, 0, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMemset(d_m, 0, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMemset(d_a, 0, BATCH * (uint64_t)alen * sizeof(uint8_t));

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

	//Parallel Granularity
	for (int i = 64; i < 1025; i *= 2) {

		float memcpy_h2d, elapsed, memcpy_d2h, total;

		for (int z = 1; z < 6; z++) {

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
			double temp = (double)BATCH / (double)i;
			dim3 blocks(ceil(temp));		
			if (z > 2) {
				threads.y = i;
				temp = (double)BATCH / ((double)threads.x * (double)threads.y);
				blocks.x = ((z == 3) ? ceil(temp / 4) : ceil(temp));
				blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
			}

			kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global : ((z == 2) ? &crypto_aead_encrypt_gpu_global_Op :
				(((z == 3) ? &crypto_aead_encrypt_gpu_rcwr_GpuTranspose : ((z == 4) ? &crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4
					: &crypto_aead_encrypt_gpu_rcwr_GpuTranspose_Op)))));
			char* kernelName = ((z == 1) ? "GPU Unoptimised" : ((z == 2) ? "GPU Op    " : (((z == 3) ? "GPU Tran" :
				((z == 4) ? "GPU TransU4" : "GPU Op Trans")))));

			//Kernel execution
			memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaEventRecord(start);
			kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH,i);

			double Ttime = 0;
			if (z < 3)
				total = memcpy_h2d + elapsed + memcpy_d2h;
			else {
				total = memcpy_h2d + trans + elapsed + memcpy_d2h;
				Ttime = trans;
			}

			printf("%s\t %u \t\t%.6f\t%.6f \t%.6f  \t%.f \t\t%.f\n", kernelName, threads.x, memcpy_h2d,
				memcpy_d2h,total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
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