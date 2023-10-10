#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> 
#include <Windows.h>
#include <time.h>
#include <math.h>
#include "params.h"
#include "permutations.h"
#include "word.h"
#include "operations.h"
#include "ascon.h"	// for optimised version

// HOST AEAD encryption
int crypto_aead_encrypt(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	(void)nsec;
	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

	/* load key and nonce */
	const uint64_t K0 = LOADBYTES(k, 8);
	const uint64_t K1 = LOADBYTES(k + 8, 8);
	const uint64_t N0 = LOADBYTES(npub, 8);
	const uint64_t N1 = LOADBYTES(npub + 8, 8);

	/* initialize */
	state_t s;
	s.x0 = ASCON_128_IV;
	s.x1 = K0;
	s.x2 = K1;
	s.x3 = N0;
	s.x4 = N1;
	P12(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	if (adlen) {
		/* full associated data blocks */
		while (adlen >= ASCON_128_RATE) {
			s.x0 ^= LOADBYTES(ad, 8);
			P6(&s);
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x0 ^= LOADBYTES(ad, adlen);
		s.x0 ^= PAD(adlen);
		P6(&s);
	}
	/* domain separation */
	s.x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		s.x0 ^= LOADBYTES(m, 8);
		STOREBYTES(c, s.x0, 8);
		P6(&s);
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	s.x0 ^= LOADBYTES(m, mlen);
	STOREBYTES(c, s.x0, mlen);
	s.x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	s.x1 ^= K0;
	s.x2 ^= K1;
	P12(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	/* set tag */
	STOREBYTES(c, s.x3, 8);
	STOREBYTES(c + 8, s.x4, 8);

	return 0;
}

//GPU Non optimised version
__global__ void crypto_aead_encrypt_gpu_global(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {
	(void)nsec;

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

	uint32_t tid = threadIdx.x;	uint32_t bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;			// message
	uint32_t idx_ia = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * (*clen) + tid * (*clen);	//instead of crypto_abytes

	/* load key and nonce */
	const uint64_t K0 = LOADBYTESG(k + idx_nk, 8);
	const uint64_t K1 = LOADBYTESG(k + 8 + idx_nk, 8);
	const uint64_t N0 = LOADBYTESG(npub + idx_nk, 8);
	const uint64_t N1 = LOADBYTESG(npub + 8 + idx_nk, 8);

	/* initialize */
	state_t s;
	s.x0 = ASCON_128_IV;
	s.x1 = K0;
	s.x2 = K1;
	s.x3 = N0;
	s.x4 = N1;

	P12G(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	if (adlen) {
		/* full associated data blocks */
		while (adlen >= ASCON_128_RATE) {
			s.x0 ^= LOADBYTESG(ad + idx_ia, 8);
			P6G(&s);
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x0 ^= LOADBYTESG(ad + idx_ia, adlen);
		s.x0 ^= PAD(adlen);
		P6G(&s);
	}
	/* domain separation */
	s.x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		s.x0 ^= LOADBYTESG(m + idx_im, 8);
		STOREBYTESG(c + idx_out, s.x0, 8);
		P6G(&s);
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	s.x0 ^= LOADBYTESG(m + idx_im, mlen);
	STOREBYTESG(c + idx_out, s.x0, mlen);
	s.x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	s.x1 ^= K0;
	s.x2 ^= K1;
	P12G(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	/* set tag */
	STOREBYTESG(c + idx_out, s.x3, 8);
	STOREBYTESG(c + idx_out + 8, s.x4, 8);
}

//GPU optimised version - use register instead of SoA & macro defination for permutation
__global__ void crypto_aead_encrypt_gpu_global_Op(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {
	(void)nsec;

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

	uint32_t tid = threadIdx.x;	uint32_t bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;			// message
	uint32_t idx_ia = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * (*clen) + tid * (*clen);	//instead of crypto_abytes

	/* load key and nonce */
	const uint64_t K0 = LOADBYTESG(k + idx_nk, 8);
	const uint64_t K1 = LOADBYTESG(k + 8 + idx_nk, 8);
	const uint64_t N0 = LOADBYTESG(npub + idx_nk, 8);
	const uint64_t N1 = LOADBYTESG(npub + 8 + idx_nk, 8);

	/* initialize */
	uint64_t x0, x1, x2, x3, x4;
	uint64_t t0, t1, t2, t3, t4;
	t0 = t1 = t2 = t3 = t4 = 0;

	x0 = ASCON_128_IV;
	x1 = K0;
	x2 = K1;
	x3 = N0;
	x4 = N1;

	P12_GO;
	x3 ^= K0;
	x4 ^= K1;

	if (adlen) {
		/* full associated data blocks */
		while (adlen >= ASCON_128_RATE) {
			x0 ^= LOADBYTESG(ad + idx_ia, 8);
			P6_GO;
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		x0 ^= LOADBYTESG(ad + idx_ia, adlen);
		x0 ^= PAD(adlen);
		P6_GO;
	}
	/* domain separation */
	x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		x0 ^= LOADBYTESG(m + idx_im, 8);
		STOREBYTESG(c + idx_out, x0, 8);
		P6_GO;
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	x0 ^= LOADBYTESG(m + idx_im, mlen);
	STOREBYTESG(c + idx_out, x0, mlen);
	x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	x1 ^= K0;
	x2 ^= K1;
	P12_GO;
	x3 ^= K0;
	x4 ^= K1;

	/* set tag */
	STOREBYTESG(c + idx_out, x3, 8);
	STOREBYTESG(c + idx_out + 8, x4, 8);
}

int main()
{
	//Set device
	int dev = 0;
	cudaDeviceProp deviceProp;
	CHECK(cudaGetDeviceProperties(&deviceProp, dev));
	CHECK(cudaSetDevice(dev));
	printf("===================================================================================================\n");

	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000, 16000000 };

#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Ascon_PG_raw", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD\s, Throughput (Times) \n");
#endif

	for (int z = 0; z < BATCH_SIZE; z++) {
		printf("\nSize Implementation : %d\n", BATCH[z]);

		//Host variable
		uint8_t* nonce, * key, * msg, * ad, * ct, * tag;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen = MAX_CIPHER_LENGTH;	// cipher length
		int result = 0;

		//Memory allocation - HOST
		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * clen * sizeof(uint8_t));
		cudaMallocHost((void**)& tag, BATCH[z] * clen * sizeof(uint8_t));

		//Initialise key, nonce, message and additional data
		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		//CPU implementation
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t = 0;

		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);

		for (int i = 0; i < BATCH[z]; i++) {
			result |= crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen), alen, 0,
				OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
			QueryPerformanceCounter(&t2);
		}
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		//Print Host Time
		printf("\nVersion \t Execution Time\t\tLatency (ms)\t\t\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host", BATCH[z], ((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("\nHost Time :\t %.6f ms\t\t\t\t\t\t%.f\n", cpu_t, BATCH[z] / (cpu_t / 1000));

		//GPU implementation
		uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c;
		uint64_t * d_clen;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)& h_c, BATCH[z] * clen * sizeof(uint8_t));				//Host Cipher
		cudaMalloc((void**)& d_c, BATCH[z] * clen * sizeof(uint8_t));					//Device Cipher
		cudaMalloc((void**)& d_n, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));		//Nonce
		cudaMalloc((void**)& d_k, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));			//Key
		cudaMalloc((void**)& d_m, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));			//Message
		cudaMalloc((void**)& d_a, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));			//Additional Data
		cudaMallocHost((void**)& d_clen, sizeof(uint64_t));

		//Memory initialisation
		memset(h_c, 0, BATCH[z] * clen * sizeof(uint8_t));
		cudaMemset(d_c, 0, BATCH[z] * clen * sizeof(uint8_t));
		cudaMemset(d_n, 0, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMemset(d_k, 0, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMemset(d_m, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));
		cudaMemset(d_a, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));
		*d_clen = MAX_CIPHER_LENGTH;

		//Warm up kernel 
		crypto_aead_encrypt_gpu_global << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k);
		crypto_aead_encrypt_gpu_global_Op << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k);

		//Memory Copy from H2D
		cudaEventRecord(start, 0);
		CHECK(cudaMemcpy(d_n, nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
		CHECK(cudaMemcpy(d_k, key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
		CHECK(cudaMemcpy(d_m, msg, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice));
		CHECK(cudaMemcpy(d_a, ad, BATCH[z] * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice));
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float memcyp_h2d;
		cudaEventElapsedTime(&memcyp_h2d, start, stop);
		printf("\nMemcpy H2D :\t %.6f ms\n\n", memcyp_h2d);

		for (int i = 1; i < 1025; i *= 2) {
	
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op << <BATCH[z] / i, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float kernel, memcpy_d2h;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU Op", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);
#ifdef WRITEFILE
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU Op");
#else
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU Op");
#endif
			memset(h_c, 0, BATCH[z] * clen * sizeof(uint8_t));


			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global << <BATCH[z] / i, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h, kernel = 0.0f;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult("GPU Ref", ct, h_c, MAX_CIPHER_LENGTH,BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], "GPU Ref");
#else
			PrintTime(ct, h_c, d_clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], "GPU Ref");
#endif

			memset(h_c, 0, BATCH[z] * clen * sizeof(uint8_t));
		}

		//Free Memory
		//Host memory
		cudaFree(nonce);
		cudaFree(key);
		cudaFree(msg);
		cudaFree(ad);
		cudaFree(ct);
		cudaFree(tag);

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

