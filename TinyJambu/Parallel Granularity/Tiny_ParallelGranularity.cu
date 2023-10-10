#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "params.h"
#include "Tiny128.h"
#include "operations.h"
//This K128 version


//Reference : Unop Ref = 0, Op Ref =1
int crypto_aead_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k,
	unsigned int v
) {
	unsigned long long i;
	unsigned int j;
	unsigned char mac[8];
	unsigned int state[4];

	//initialization stage
	initialization_CPU(k, npub, state, v);

	//process the associated data   
	process_ad_CPU(k, ad, adlen, state, v);

	//process the plaintext    
	for (i = 0; i < (mlen >> 2); i++)
	{
		state[1] ^= FrameBitsPC;
		if (v == 0) state_update_Ref(state, k, NROUND2); else state_update_OpRef(state, k, NROUND2);
		state[3] ^= ((unsigned int*)m)[i];
		((unsigned int*)c)[i] = state[2] ^ ((unsigned int*)m)[i];
	}
	// if mlen is not a multiple of 4, we process the remaining bytes
	if ((mlen & 3) > 0)
	{
		state[1] ^= FrameBitsPC;
		if (v == 0) state_update_Ref(state, k, NROUND2);  else state_update_OpRef(state, k, NROUND2);
		for (j = 0; j < (mlen & 3); j++)
		{
			((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
			c[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(i << 2) + j];
		}
		state[1] ^= mlen & 3;
	}

	//finalization stage, we assume that the tag length is 8 bytes
	state[1] ^= FrameBitsFinalization;
	if (v == 0) state_update_Ref(state, k, NROUND2); else state_update_OpRef(state, k, NROUND2);
	((unsigned int*)mac)[0] = state[2];

	state[1] ^= FrameBitsFinalization;
	if (v == 0) state_update_Ref(state, k, NROUND1);  else state_update_OpRef(state, k, NROUND1);
	((unsigned int*)mac)[1] = state[2];

	*clen = mlen + 8;
	for (j = 0; j < 8; j++) c[mlen + j] = mac[j];

	return 0;
}


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

		unsigned long long i;
		unsigned int j;
		unsigned char mac[8];
		unsigned int state[4];

		//initialization stage
		initialization_OpGPU(K, N, state);

		//process the associated data   
		process_ad_OpGPU(K, A, adlen, state);

		//process the plaintext    
		for (i = 0; i < (mlen >> 2); i++)
		{
			state[1] ^= FrameBitsPC;
			state_update_OpRefG(state, K, NROUND2);

			state[3] ^= ((unsigned int*)M)[i];
			((unsigned int*)C)[i] = state[2] ^ ((unsigned int*)M)[i];
		}
		// if mlen is not a multiple of 4, we process the remaining bytes
		if ((mlen & 3) > 0)
		{
			state[1] ^= FrameBitsPC;
			state_update_OpRefG(state, K, NROUND2);

#pragma unroll
			for (j = 0; j < (mlen & 3); j++)
			{
				((unsigned char*)state)[12 + j] ^= M[(i << 2) + j];
				C[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ M[(i << 2) + j];
			}
			state[1] ^= mlen & 3;
		}

		//finalization stage, we assume that the tag length is 8 bytes
		state[1] ^= FrameBitsFinalization;
		state_update_OpRefG(state, K, NROUND2);

		((unsigned int*)mac)[0] = state[2];

		state[1] ^= FrameBitsFinalization;
		state_update_OpRefG(state, K, NROUND1);

		((unsigned int*)mac)[1] = state[2];

		*clen = mlen + 8;
		for (j = 0; j < 8; j++) C[mlen + j] = mac[j];
	}
}


__global__ void crypto_aead_encrypt_gpu_global_Op(
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

		unsigned long long i;
		unsigned int j;
		unsigned char mac[8];
		unsigned int state[4];

		//initialization stage
		initialization_GPU_Op(K, N, state);

		//process the associated data   
		process_ad_GPU_Op(K, A, adlen, state);

		//process the plaintext - unroll 2  
		for (i = 0; i < (mlen >> 2); i += 2)
		{
			state[1] ^= FrameBitsPC;
			state_update_OpRef_Register(state, K, NROUND2);

			state[3] ^= ((unsigned int*)M)[i];
			((unsigned int*)C)[i] = state[2] ^ ((unsigned int*)M)[i];

			//2nd time unroll
			state[1] ^= FrameBitsPC;
			state_update_OpRef_Register(state, K, NROUND2);

			state[3] ^= ((unsigned int*)M)[i + 1];
			((unsigned int*)C)[i + 1] = state[2] ^ ((unsigned int*)M)[i + 1];

		}

		// if mlen is not a multiple of 4, we process the remaining bytes
		if ((mlen & 3) > 0)
		{
			state[1] ^= FrameBitsPC;
			state_update_OpRef_Register(state, K, NROUND2);

			for (j = 0; j < (mlen & 3); j++)
			{
				((unsigned char*)state)[12 + j] ^= M[(i << 2) + j];
				C[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ M[(i << 2) + j];
			}
			state[1] ^= mlen & 3;
		}

		//finalization stage, we assume that the tag length is 8 bytes
		state[1] ^= FrameBitsFinalization;
		state_update_OpRef_Register(state, K, NROUND2);

		((unsigned int*)mac)[0] = state[2];

		state[1] ^= FrameBitsFinalization;
		state_update_OpRef_Register(state, K, NROUND1);

		((unsigned int*)mac)[1] = state[2];

		*clen = mlen + 8;
		for (j = 0; j < 8; j++) C[mlen + j] = mac[j];
	}
}

__global__ void crypto_aead_encrypt_gpu_global_Op_KeyInversion(
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
		uint8_t* key = const_cast<uint8_t*>(k) + offset_key;
		uint8_t* K = key;

		unsigned long long i;
		unsigned int j;
		unsigned char mac[8];
		unsigned int state[4];

		//keyInversion
		for (uint8_t i = 0; i < CRYPTO_KEYBYTES; i++) {
			K[i] = ~key[i];
		}

		//initialization stage
		initialization_OpGPU_Key(K, N, state);

		//process the associated data   
		process_ad_OpGPU_Key(K, A, adlen, state);

		//process the plaintext - unroll 2  
		for (i = 0; i < (mlen >> 2); i += 2)
		{
			state[1] ^= FrameBitsPC;
			state_update_Op_Key(state, K, NROUND2);

			state[3] ^= ((unsigned int*)M)[i];
			((unsigned int*)C)[i] = state[2] ^ ((unsigned int*)M)[i];

			//2nd time unroll
			state[1] ^= FrameBitsPC;
			state_update_Op_Key(state, K, NROUND2);

			state[3] ^= ((unsigned int*)M)[i + 1];
			((unsigned int*)C)[i + 1] = state[2] ^ ((unsigned int*)M)[i + 1];

		}

		// if mlen is not a multiple of 4, we process the remaining bytes
		if ((mlen & 3) > 0)
		{
			state[1] ^= FrameBitsPC;
			state_update_Op_Key(state, K, NROUND2);

			for (j = 0; j < (mlen & 3); j++)
			{
				((unsigned char*)state)[12 + j] ^= M[(i << 2) + j];
				C[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ M[(i << 2) + j];
			}
			state[1] ^= mlen & 3;
		}

		//finalization stage, we assume that the tag length is 8 bytes
		state[1] ^= FrameBitsFinalization;
		state_update_Op_Key(state, K, NROUND2);

		((unsigned int*)mac)[0] = state[2];

		state[1] ^= FrameBitsFinalization;
		state_update_Op_Key(state, K, NROUND1);

		((unsigned int*)mac)[1] = state[2];

		*clen = mlen + 8;
		for (j = 0; j < 8; j++) C[mlen + j] = mac[j];
	}
}

int main()
{

#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Tiny128_PG.csv", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	////64K, 256K, 1M, 4M, 10M ->64000,256000,1000000,4000000,16000000
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
			int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), Ref);
		}
		QueryPerformanceCounter(&t2);
		cpu_tRef += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		printf("\nVersion\t\tLatency (ms)\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-Ref", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_tRef, cpu_tRef, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tRef) * 8, 0.0, cpu_tRef, 0.0, BATCH[z] / (cpu_tRef / 1000), 0.0);
#endif
		printf("\nHost Ref Time :\t %.6f ms\t\t\t%.f\n", cpu_tRef, BATCH[z] / (cpu_tRef / 1000));


		//// Op Ref
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {

			int result = crypto_aead_encrypt(OFFSET(ct_Op, i, clen2), &clen2, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), Op);

		}
		QueryPerformanceCounter(&t2);
		cpu_tOp += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host-Op", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_tOp, cpu_tOp, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_tOp) * 8, 0.0, cpu_tOp, 0.0, BATCH[z] / (cpu_tOp / 1000), 0.0);
#endif
		printf("Host Op Time :\t %.6f ms\t\t\t%.f\n", cpu_tOp, BATCH[z] / (cpu_tOp / 1000));


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
		crypto_aead_encrypt_gpu_global_OpRef << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_Op << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_Op_KeyInversion << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);

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

			//Op Ref
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_OpRef << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef, 2 is Op refined with register
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

			float cpu_t = cpu_tOp;
			char * kernelName = "GPU Ref";
			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH, BATCH[z], i);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], kernelName);
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], kernelName);
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Op - Register 
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]); //0 is Ref, 1 is OpRef, 2 is Op refined with register
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

			cpu_t = cpu_tOp;
			kernelName = "GPU Op Reg";
			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH, BATCH[z],i);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], kernelName);
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], kernelName);
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Op - Key Inverse 
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op_KeyInversion << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
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

			cpu_t = cpu_tOp;
			kernelName = "GPU Op Inv";
			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH, BATCH[z], i);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], kernelName);
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], kernelName);
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
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