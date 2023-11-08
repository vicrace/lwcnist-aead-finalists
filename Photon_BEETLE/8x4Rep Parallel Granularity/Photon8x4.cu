#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <Windows.h>
#include "params.h"
#include "operations.h"
#include "photonBeetle.h"

static int crypto_aead_encrypt(
	const uint8_t* key,   // 16 -bytes secret key
	const uint8_t* nonce, // 16 -bytes public message nonce
	const uint8_t* data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t* txt,   // N -bytes plain text | N >= 0
	uint8_t* enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t* tag          // 16 -bytes authentication tag
)
{
	if (check_rate(R)) {

		uint8_t* C = enc;
		uint8_t* T = tag;
		const uint8_t* M = txt;
		const uint8_t* A = data;
		const uint8_t* N = nonce;
		const uint8_t* K = key;

		uint8_t state[32];

		memcpy(state, N, NONCE_LEN);
		memcpy(state + NONCE_LEN, K, KEY_LEN);

		if ((dlen == 0) && (mlen == 0)) [[unlikely]] {
		  state[31] ^= (1 << 5);
		  gen_tag(state, T, TAG_LEN);

		  return 0;
		}

		const bool f0 = mlen > 0;
		const bool f1 = (dlen & (R - 1)) == 0;
		const bool f2 = dlen > 0;
		const bool f3 = (mlen & (R - 1)) == 0;

		const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;
		const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

		if (dlen > 0) [[likely]] {
		  absorb(state, A, dlen, C0,R);
		}

			if (mlen > 0) [[likely]] {
			  for (size_t off = 0; off < mlen; off += R) {
				photon256(state);
				const auto len = ((R < (mlen - off)) ? R : (mlen - off));
				rho(state, M + off, C + off, len);
			  }

			  state[31] ^= (C1 << 5);
			}

		gen_tag(state, T, TAG_LEN);
		return 0;
	}
	return -1;
}

__global__ void crypto_aead_encrypt_gpu_global(
	const uint8_t* key,   // 16 -bytes secret key
	const uint8_t* nonce, // 16 -bytes public message nonce
	const uint8_t* data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t* txt,   // N -bytes plain text | N >= 0
	uint8_t* enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t* tag          // 16 -bytes authentication tag
) {
	if (check_rateG(R)) {

		int tid = threadIdx.x, bid = blockIdx.x;
		uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;
		uint32_t idx_ia = bid * blockDim.x * dlen + tid * dlen;			// AD
		uint32_t idx_in = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t idx_ik = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t idx_out = bid * blockDim.x * MAX_CIPHER_LENGTH + (tid * MAX_CIPHER_LENGTH);	//instead of crypto_abytes
		uint32_t idx_tag = bid * blockDim.x * TAG_LEN + (tid * TAG_LEN);	//instead of crypto_abytes

		uint8_t* C = enc + idx_out;
		uint8_t* T = tag + idx_tag;
		const uint8_t* M = txt + idx_im;
		const uint8_t* A = data + idx_ia;
		const uint8_t* N = nonce + idx_in;
		const uint8_t* K = key + idx_ik;

		uint8_t state[32];

		memcpy(state, N, NONCE_LENG);
		memcpy(state + NONCE_LENG, K, KEY_LENG);

		if ((dlen == 0) && (mlen == 0)) [[unlikely]] {
		  state[31] ^= (1 << 5);
		  gen_tagG(state, T, TAG_LENG);
		}

		const bool f0 = mlen > 0;
		const bool f1 = (dlen & (R - 1)) == 0;
		const bool f2 = dlen > 0;
		const bool f3 = (mlen & (R - 1)) == 0;

		const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;
		const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

		if (dlen > 0) [[likely]] {
		  absorbG(state, A, dlen, C0,R);
		}

			if (mlen > 0) [[likely]] {
			  for (size_t off = 0; off < mlen; off += R) {
				photon256G(state);
				const auto len = ((R < (mlen - off)) ? R : (mlen - off));
				rhoG(state, M + off, C + off, len);
			  }

			  state[31] ^= (C1 << 5);
			}

		gen_tagG(state, T, TAG_LENG);
	}
}


__global__ void crypto_aead_encrypt_gpu_global_Op(
	const uint8_t* key,   // 16 -bytes secret key
	const uint8_t* nonce, // 16 -bytes public message nonce
	const uint8_t* data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t* txt,   // N -bytes plain text | N >= 0
	uint8_t* enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t* tag          // 16 -bytes authentication tag
) {
	if (check_rateG(R)) {

		int tid = threadIdx.x, bid = blockIdx.x;
		uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;
		uint32_t idx_ia = bid * blockDim.x * dlen + tid * dlen;			// AD
		uint32_t idx_in = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t idx_ik = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t idx_out = bid * blockDim.x * MAX_CIPHER_LENGTH + (tid * MAX_CIPHER_LENGTH);	//instead of crypto_abytes
		uint32_t idx_tag = bid * blockDim.x * TAG_LEN + (tid * TAG_LEN);	//instead of crypto_abytes

		uint8_t* C = enc + idx_out;
		uint8_t* T = tag + idx_tag;
		const uint8_t* M = txt + idx_im;
		const uint8_t* A = data + idx_ia;
		const uint8_t* N = nonce + idx_in;
		const uint8_t* K = key + idx_ik;

		uint8_t state[32];

		memcpy(state, N, NONCE_LENG);
		memcpy(state + NONCE_LENG, K, KEY_LENG);

		if ((dlen == 0) && (mlen == 0)) [[unlikely]] {
			state[31] ^= (1 << 5);
			gen_tagG_Op(state, T, TAG_LENG);
		}

		const bool f0 = mlen > 0;
		const bool f1 = (dlen & (R - 1)) == 0;
		const bool f2 = dlen > 0;
		const bool f3 = (mlen & (R - 1)) == 0;

		const uint8_t C0 = (f0 && f1) ? 1 : f0 ? 2 : f1 ? 3 : 4;
		const uint8_t C1 = (f2 && f3) ? 1 : f2 ? 2 : f3 ? 5 : 6;

		if (dlen > 0) [[likely]] {
		  absorbG_Op(state, A, dlen, C0,R);
		}

			if (mlen > 0) [[likely]] {
			  for (size_t off = 0; off < mlen; off += R) {
				photon256G_Op(state);
				const auto len = ((R < (mlen - off)) ? R : (mlen - off));
				rhoG(state, M + off, C + off, len);
			  }

			  state[31] ^= (C1 << 5);
			}

		gen_tagG_Op(state, T, TAG_LENG);
	}
}



int main()
{

#ifdef WRITEFILE
	//FILE writing
	FILE* fpt;
	fpt = fopen("Photon_8x4_PG.csv", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD\s, Throughput(Times) \n");
#endif

	////64K, 256K, 1M, 4M, 10M ->64000,256000,1000000,4000000,10000000
	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		printf("\nSize Implementation : %d\n", BATCH[z]);

		//Host variable
		uint8_t* nonce, * key, * msg, * ad, * ct, * tag;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen = MLEN;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t = 0;

		//Memory Allocation - HOST
		cudaMallocHost((void**)&key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)&nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)&msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)&ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)&ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)&tag, BATCH[z] * TAG_LEN * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);


		for (int i = 0; i < BATCH[z]; i++) {
			QueryPerformanceFrequency(&frequency);
			QueryPerformanceCounter(&t1);
			int result = crypto_aead_encrypt(OFFSET(key, i, CRYPTO_KEYBYTES), OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(ad, i, alen),
				MAX_ASSOCIATED_DATA_LENGTH, OFFSET(msg, i, mlen), OFFSET(ct, i, clen), MAX_MESSAGE_LENGTH, OFFSET(tag, i, TAG_LEN));
			QueryPerformanceCounter(&t2);

			cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
		}
		//Print Host Time
		printf("\nVersion \t Latency (ms)\t\t\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, cpu_t, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("\nHost Time :\t %.6f ms\t\t\t\t\t\t%.f\n", cpu_t, BATCH[z] / (cpu_t / 1000));

		//GPU implementation
		uint8_t* d_n, * d_k, * d_a, * d_m, * d_c, * h_c, * h_t, * d_t;
		uint64_t* d_clen;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)&h_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMalloc((void**)&d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)&d_n, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
		cudaMalloc((void**)&d_k, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
		cudaMalloc((void**)&d_m, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));				//Message
		cudaMalloc((void**)&d_a, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
		cudaMalloc((void**)&d_t, BATCH[z] * (uint64_t)TAG_LEN * sizeof(uint8_t));				//Message
		cudaMalloc((void**)&h_t, BATCH[z] * (uint64_t)TAG_LEN * sizeof(uint8_t));				//Additional Data
		cudaMallocHost((void**)&d_clen, sizeof(uint64_t));

		//Memory initialisation
		memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_n, 0, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMemset(d_k, 0, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMemset(d_m, 0, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));
		cudaMemset(d_a, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));
		cudaMemset(d_t, 0, BATCH[z] * (uint64_t)TAG_LEN * sizeof(uint8_t));
		*d_clen = MAX_CIPHER_LENGTH;

		//Warm up kernel 
		cudaEventRecord(start, 0);
		crypto_aead_encrypt_gpu_global << <BATCH[z] / 1, 1 >> > (d_k, d_n, d_a, MAX_ASSOCIATED_DATA_LENGTH, d_m, d_c,
			MAX_MESSAGE_LENGTH, d_t);
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
		float memcyp_h2d = 0;
		cudaEventElapsedTime(&memcyp_h2d, start, stop);
		printf("\nMemcpy H2D :\t %.6f ms\t(%f GB/s)\n\n", memcyp_h2d, ((BATCH[z] * mlen * sizeof(uint8_t)) * 1e-6) / memcyp_h2d);

		//Parallel Granularity
		for (int i = 1; i < 1025; i *= 2) {

			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);

			//UnOp
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global << <blocks, i >> > (d_k, d_n, d_a, MAX_ASSOCIATED_DATA_LENGTH, d_m, d_c, MAX_MESSAGE_LENGTH, d_t);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);


			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaMemcpy(h_t, d_t, BATCH[z] * TAG_LEN * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_d2h = 0;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

#ifdef WRITEFILE
			PrintTime(ct, h_c, (uint64_t*)MAX_CIPHER_LENGTH, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], tag, h_t, "8x4 Ref");
#else
			PrintTime(ct, h_c, (uint64_t*)MAX_CIPHER_LENGTH, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], tag, h_t, "8x4 Ref");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


			//Optimised
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_Op << <blocks, i >> > (d_k, d_n, d_a, MAX_ASSOCIATED_DATA_LENGTH, d_m, d_c, MAX_MESSAGE_LENGTH, d_t);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaMemcpy(h_t, d_t, BATCH[z] * TAG_LEN * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

#ifdef WRITEFILE
			PrintTime(ct, h_c, (uint64_t*)MAX_CIPHER_LENGTH, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, fpt, BATCH[z], tag, h_t, "8x4 Op");
#else
			PrintTime(ct, h_c, (uint64_t*)MAX_CIPHER_LENGTH, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t, NULL, BATCH[z], tag, h_t, "8x4 Op");
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
		cudaFree(tag);

		//Device memory
		cudaFree(d_n);
		cudaFree(d_k);
		cudaFree(d_a);
		cudaFree(d_m);
		cudaFree(d_c);
		cudaFree(h_c);
		cudaFree(h_t);
		cudaFree(d_t);
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
