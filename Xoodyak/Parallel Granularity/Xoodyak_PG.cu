#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include <string.h>
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

__global__ void crypto_aead_encrypt_gpu_global__Fine(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec, const uint8_t * npub, const uint8_t * k)
{
	Xoodyak_Instance    instance;

	(void)nsec;

	int tid = threadIdx.x, bid = blockIdx.x;
	uint8_t* C = c + (bid * blockDim.x * (*clen) + ((tid / fineLevel) * (*clen)));
	uint8_t * T = c + mlen + (bid * blockDim.x * (*clen) + ((tid / fineLevel) * (*clen)));
	const uint8_t * M = m + (bid * blockDim.x * mlen + ((tid / fineLevel) * mlen));
	const uint8_t * A = ad + (bid * blockDim.x * adlen + ((tid / fineLevel) * adlen));
	const uint8_t * N = npub + (bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES));
	const uint8_t * K = k + (bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES));

	Xoodyak_InitializeG__Fine(&instance, K, CRYPTO_KEYBYTES, N, CRYPTO_NPUBBYTES, NULL, 0);
	Xoodyak_AbsorbG__Fine(&instance, A, (size_t)adlen);
	Xoodyak_EncryptG__Fine(&instance, M, C, (size_t)mlen);
	Xoodyak_SqueezeAnyG__Fine(&instance, C + mlen, CRYPTO_ABYTES, 0x40);
	*clen = mlen + CRYPTO_ABYTES;

}


int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	char writeFile[100];
	char fineLvl[1];
	strcpy(writeFile, "Xoodyak_PG_F");
	sprintf(fineLvl, "%d", fineLevel);
	strcat(writeFile, fineLvl);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s, Throughput (speed up)\n");

#endif


	////64K, 256K, 1M, 4M, 10M ->64000,256000,1000000,4000000,10000000
	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ct, * msg2;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen, mlen2;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t = 0;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		cudaMallocHost((void**)& msg2, BATCH[z] * mlen * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {
			int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
		}
		QueryPerformanceCounter(&t2);
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
		//Print Host Time
		printf("\nVersion \tLatency (ms)\t\t\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("\nHost Time :\t %.6f ms\t\t\t\t\t\t%.f\n", cpu_t, BATCH[z] / (cpu_t / 1000));


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

		//Warm up kernel 
		cudaEventRecord(start, 0);
		crypto_aead_encrypt_gpu_global << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float warmup;
		cudaEventElapsedTime(&warmup, start, stop);
		printf("Warmup :\t %.6f ms", warmup);

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

		//Parallel Granularity
		for (int i = 1; i < 1025; i *= 2) {

			//Un op
			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
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
			checkResult("GPU Ref", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU Ref");
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU Ref");
#endif

			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));



			//Optimised
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("GPU Op", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU Op");
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU Op");
#endif

			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Fine Grain
			if (i == fineLevel) {
				size_t size = BATCH[z] * (*d_clen) * sizeof(uint8_t);
				dim3 threads(Tlimit); //fine grain each block max 512 threads to divide by 2/4.
				double temp = ((double)BATCH[z] / (Tlimit / (double)fineLevel));
				dim3 blocks2(ceil(temp));		//for unoptimised

				cudaEventRecord(start, 0);
				crypto_aead_encrypt_gpu_global__Fine << <blocks2, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				kernel = 0;
				cudaEventElapsedTime(&kernel, start, stop);

				//Memory Copy from D2H
				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_d2h = 0;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult("Fine", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);
				memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

				float total = memcyp_h2d + kernel + memcpy_d2h;
				printf("KernelT%d :\t %.6f ms\t %.2f times\t%.f\t%.2f more \t %s%d\n", i, total, (cpu_t / total), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_t / 1000)), "Fine ", fineLevel);
#ifdef WRITEFILE
				fprintf(fpt, "T%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f, %s%d\n", i, BATCH[z], (size * 2e-6) / total, total, (cpu_t / total), ((size * 2e-6) / total) * 8, memcyp_h2d, kernel, (cpu_t / kernel), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_t / 1000)), "Fine ", fineLevel);
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

	}
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();
	return 0;
}