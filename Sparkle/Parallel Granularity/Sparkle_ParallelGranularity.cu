#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "params.h"
#include "sparkle.h"
#include "sparkleGPU.h"
#include "operations.h"

int crypto_aead_encrypt_Ref(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k) {

	SparkleState state;
	size_t msize = (size_t)mlen;
	size_t adsize = (size_t)adlen;

	Initialize(&state, k, npub);
	if (adsize) ProcessAssocData(&state, ad, adsize);
	if (msize) ProcessPlainText(&state, c, m, msize);
	Finalize(&state, k);
	GenerateTag(&state, (c + msize));
	*clen = msize;
	*clen += TAG_BYTES;

	return 0;
}

int crypto_aead_encrypt_Op(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k) {

	uint32_t state[STATE_WORDS];
	size_t msize = (size_t)mlen;
	size_t adsize = (size_t)adlen;

	Initialize_Op(state, k, npub);
	if (adsize) ProcessAssocData_Op(state, ad, adsize);
	if (msize) ProcessPlainText_Op(state, c, m, msize);
	Finalize_Op(state, k);
	GenerateTag_Op(state, (c + msize));
	*clen = msize;
	*clen += TAG_BYTES;

	return 0;
}


__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch) {

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
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		SparkleState state;
		size_t msize = (size_t)mlen;
		size_t adsize = (size_t)adlen;

		Initialize_GPU(&state, K, N);
		if (adsize) ProcessAssocData_GPU(&state, A, adsize);
		if (msize) ProcessPlainText_GPU(&state, C, M, msize);
		Finalize_GPU(&state, K);
		GenerateTag_GPU(&state, (C + msize));
		*clen = msize;
		*clen += TAG_BYTES;
	}

}


//Optimise Reference
__global__ void crypto_aead_encrypt_gpu_global_OpRef(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch) {

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
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		uint32_t state[STATE_WORDS];
		size_t msize = (size_t)mlen;
		size_t adsize = (size_t)adlen;

		Initialize_Op_GPU(state, K, N);
		if (adsize) ProcessAssocData_Op_GPU(state, A, adsize);
		if (msize) ProcessPlainText_Op_GPU(state, C, M, msize);
		Finalize_Op_GPU(state, K);
		GenerateTag_Op_GPU(state, (C + msize));
		*clen = msize;
		*clen += TAG_BYTES;
	}
}


//Optimisation - unroll the function loop, use shared memory for their buffers & move all main function in kernel, reduce passing data.
__global__ void crypto_aead_encrypt_gpu_global_Op(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int Batch)
{

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
		uint8_t* N = const_cast<uint8_t*>(npub) + offset_nonce;
		uint8_t* K = const_cast<uint8_t*>(k) + offset_key;

		uint32_t state[STATE_WORDS];
		size_t msize = (size_t)mlen;
		size_t adsize = (size_t)adlen;

		//Initialization
		memcpy(state, N, NONCE_BYTES);
		memcpy((state + RATE_WORDS), K, KEY_BYTES);
		sparkle_opt_GPU_Op(state, STATE_BRANS, SPARKLE_STEPS_BIG);

		//Process associate data
		if (adsize) {
			int aligned = ((size_t)A) % UI32_ALIGN_BYTES == 0;

			while (adsize > RATE_BYTES) {
				// combined Rho and rate-whitening operation
				rho_whi_aut_Op_GPU_Op(state, A, aligned);
				// execute SPARKLE with slim number of steps
				sparkle_opt_GPU_Op(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
				adsize -= RATE_BYTES;
				A += RATE_BYTES;
			}
			state[STATE_WORDS - 1] ^= ((adsize < RATE_BYTES) ? CONST_A0 : CONST_A1);
			rho_whi_aut_last_Op_GPU_Op(state, A, adsize);
			sparkle_opt_GPU_Op(state, STATE_BRANS, SPARKLE_STEPS_BIG);
		}

		//Process message
		if (msize) {
			int aligned = (((size_t)M) | ((size_t)C)) % UI32_ALIGN_BYTES == 0;

			while (msize > RATE_BYTES) {
				rho_whi_enc_Op_GPU_Op(state, C, M, aligned);
				sparkle_opt_GPU_Op(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
				msize -= RATE_BYTES;
				C += RATE_BYTES;
				M += RATE_BYTES;
			}

			state[STATE_WORDS - 1] ^= ((msize < RATE_BYTES) ? CONST_M2 : CONST_M3);
			rho_whi_enc_last_Op_GPU_Op(state, C, M, msize);
			sparkle_opt_GPU_Op(state, STATE_BRANS, SPARKLE_STEPS_BIG);
		}

		//Finalization
		uint32_t buffer[TAG_WORDS];
		int i;

		memcpy(buffer, K, KEY_BYTES);
		for (i = 0; i < KEY_WORDS; i++)
			state[RATE_WORDS + i] ^= buffer[i];

		//Generate Tag
		memcpy((C + msize), (state + RATE_WORDS), TAG_BYTES);

		*clen = msize;
		*clen += TAG_BYTES;
	}
}

int main()
{

#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Sparkle256_PGResult.csv", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ct, * ct_Op;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen = MAX_CIPHER_LENGTH, clen2 = MAX_CIPHER_LENGTH;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_tRef = 0, cpu_tOp = 0;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)& ct_Op, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		//// REF
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

			int result = crypto_aead_encrypt_Ref(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
			print('cr', ct + (i * clen), clen);
#endif
		}
		QueryPerformanceCounter(&t2);
		cpu_tRef = 0;
		cpu_tRef += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
		printf("\nVersion\t\tLatency (ms)\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-Ref", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_tRef, cpu_tRef, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tRef) * 8, 0.0, cpu_tRef, 0.0, BATCH[z] / (cpu_tRef / 1000), 0.0);
#endif
		printf("\nHost Ref Time :\t %.6f ms\t%.f\n", cpu_tRef, BATCH[z] / (cpu_tRef / 1000));


		//// Op Ref
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {

			int result = crypto_aead_encrypt_Op(OFFSET(ct_Op, i, clen2), &clen2, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

#ifdef PRINTC
			print('co', ct_Op + (i * clen), clen);
#endif
		}
		QueryPerformanceCounter(&t2);
		cpu_tOp = 0;
		cpu_tOp += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-Op", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_tOp, cpu_tOp, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tOp) * 8, 0.0, cpu_tOp, 0.0, BATCH[z] / (cpu_tOp / 1000), 0.0);
#endif
		printf("Host Op Time :\t %.6f ms\t%.f\n", cpu_tOp, BATCH[z] / (cpu_tOp / 1000));

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
		crypto_aead_encrypt_gpu_global << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_OpRef << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_Op << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);

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
			int blocks = ((BATCH[z] / i) < 1) ? 1 : ceil((double)BATCH[z] / (double)i);

			//Ref GPU
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef
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
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tRef, fpt, BATCH[z], "GPU Ref");
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tRef, NULL, BATCH[z], "GPU Ref");
#endif

			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Ref Op GPU
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_OpRef << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef
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
			checkResult("GPU Op Ref", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct_Op, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tOp, fpt, BATCH[z], "GPU OpRef");
#else
			PrintTime(ct_Op, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tOp, NULL, BATCH[z], "GPU OpRef");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			// Op GPU
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
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
			checkResult("GPU Op", ct_Op, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct_Op, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tOp, fpt, BATCH[z], "GPU Op");
#else
			PrintTime(ct_Op, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_tOp, NULL, BATCH[z], "GPU Op");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
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
