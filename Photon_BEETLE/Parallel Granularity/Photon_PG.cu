#include "cuda_runtime.h"
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
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k, int mode)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;
	uint32_t idx_ia = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * MAX_CIPHER_LENGTH + tid * MAX_CIPHER_LENGTH;

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

__global__ void crypto_aead_encrypt_gpu_global_Fine(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k)
{
	int i, tid = threadIdx.x, bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);
	uint32_t idx_ia = bid * blockDim.x * adlen + ((tid / fineLevel) * adlen);			// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * (*clen) + ((tid / fineLevel) * (*clen));	//instead of crypto_abytes

	uint8_t* C = c + idx_out;
	uint8_t* T = c + mlen + idx_out;
	const uint8_t* M = m + idx_im;
	const uint8_t* A = ad + idx_ia;
	const uint8_t* N = npub + idx_nk;
	const uint8_t* K = k + idx_nk;

	uint8_t State[STATE_INBYTES] = { 0 };
	uint8_t c0;
	uint8_t c1;

	(void)nsec;

	memcpy(State, N, NOUNCE_INBYTES);
	memcpy(State + NOUNCE_INBYTES, K, KEY_INBYTES);

	if ((adlen == 0) && (mlen == 0))
	{
		State[STATE_INBYTES - 1] ^= (1 << LAST_THREE_BITS_OFFSET);
		TAGG_Fine(T, State);
		*clen = TAG_INBYTES;
	}

	c0 = selectConstG((mlen != 0), ((adlen % RATE_INBYTES) == 0), 1, 2, 3, 4);
	c1 = selectConstG((adlen != 0), ((mlen % RATE_INBYTES) == 0), 1, 2, 5, 6);

	if (adlen != 0) HASHG_Fine(State, A, adlen, c0);
	if (mlen != 0) ENCorDECG_Fine(State, C, M, mlen, c1, ENC);

	TAGG_Fine(T, State);
	*clen = mlen + TAG_INBYTES;
}

int main()
{
#ifdef WRITEFILE
	//FILE writing
	FILE* fpt;
	fpt = fopen("Photon_PG_raw.csv", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s, Throughput (speed up)\n");
#endif

	////64K, 256K, 1M, 4M, 10M ->64000,256000,1000000,4000000,10000000
	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int z = 0; z < BATCH_SIZE; z++) {
		//Host variable
		uint8_t* nonce, * key, * msg, * ad, * ct, * ct2;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t = 0;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		//Memory Allocation - HOST
		cudaMallocHost((void**)&key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)&nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)&msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)&ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)&ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)&ct2, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);
		BuildTableSCShRMCS();

		//Host - no precomputed
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {
			int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), 0); // 0 is no table
		}
		QueryPerformanceCounter(&t2);
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		//Print Host Time
		printf("Version\t\t\tMemcpyH2D\tMemcpyD2H\t\tTotal\t\tAEAD/s\n\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s %s, %d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", "Noprecomputed", ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, 0.0, cpu_t, 0.0, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("Host No-precomp\t\t%.6f\t%.6f\t\t%.6f \t\t%.f \n", 0.0, 0.0, cpu_t, BATCH[z] / (cpu_t / 1000));


		//With precomputed table
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {
			int result = crypto_aead_encrypt(OFFSET(ct2, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES), 1); //1 is have table
		}
		QueryPerformanceCounter(&t2);
		cpu_t = 0;
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

		checkResult("H", ct, ct2, MAX_CIPHER_LENGTH, BATCH[z], 128);
#ifdef WRITEFILE
		fprintf(fpt, "%s %s, %d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", "Precomputed", ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, 0.0, cpu_t, 0.0, 0.0, BATCH[z] / (cpu_t / 1000), 0.0);
#endif
		printf("Host Precomp\t\t%.6f\t%.6f\t\t%.6f \t\t%.f \n", 0.0, 0.0, cpu_t, BATCH[z] / (cpu_t / 1000));

		//GPU implementation
		uint8_t* d_n, * d_k, * d_a, * d_m, * d_c, * h_c;
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
		cudaMallocHost((void**)&d_clen, sizeof(uint64_t));

		//Memory initialisation
		memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMemset(d_n, 0, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMemset(d_k, 0, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMemset(d_m, 0, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t));
		cudaMemset(d_a, 0, BATCH[z] * (uint64_t)alen * sizeof(uint8_t));

		//Memory Copy from H2D
		cudaEventRecord(start, 0);
		cudaMemcpy(d_n, nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_k, key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_m, msg, BATCH[z] * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_a, ad, BATCH[z] * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float memcpy_h2d;
		cudaEventElapsedTime(&memcpy_h2d, start, stop);


		for (int i = 1; i < 1025; i *= 2) {

			float elapsed, memcpy_d2h, total;
			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);

			for (int q = 1; q <= 4; q++) {	//No-precomp , pre-comp, share memory, warp shuffle
				char* modeName = ((q == 1) ? "No-Precom" : ((q == 2) ? "Pre-comp" : ((q == 3) ? "Shared Mem" : "Warp Shuffle")));

				//Kernel execution
				cudaEventRecord(start);
				crypto_aead_encrypt_gpu_global << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, 0, d_n, d_k, q);
				cudaEventRecord(stop);
				cudaEventSynchronize(stop);
				cudaEventElapsedTime(&elapsed, start, stop);

				//Memory Copy from D2H
				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[z] * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult(modeName, ct, h_c, MAX_CIPHER_LENGTH, BATCH[z], i);

				total = memcpy_h2d + elapsed + memcpy_d2h;
#ifdef WRITEFILE
				PrintTime(ct, h_c, &clen, i, memcpy_h2d, elapsed, memcpy_d2h, cpu_t, fpt, BATCH[z], modeName);
#else
				PrintTime(ct, h_c, &clen, i, memcpy_h2d, elapsed, memcpy_d2h, cpu_t, NULL, BATCH[z], modeName);
#endif
				memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			}
		}

		//Fine Grain
		size_t size = BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t);
		float elapsed = 0, memcpy_d2h = 0, total = 0;
		int blocks = (ceil((BATCH[z] / (Tlimit / (double)fineLevel))) < 1) ? 1 : ceil((BATCH[z] / (Tlimit / (double)fineLevel)));

		cudaEventRecord(start, 0);
		crypto_aead_encrypt_gpu_global_Fine << <blocks, fineLevel >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		cudaEventElapsedTime(&elapsed, start, stop);

		//Memory Copy from D2H
		cudaEventRecord(start, 0);
		cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		cudaEventElapsedTime(&memcpy_d2h, start, stop);
		checkResult("Fine", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z], 128);
		memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));


		total = memcpy_h2d + elapsed + memcpy_d2h;
		printf("FineT%d :\t\t %.6f ms \t %.6f ms\t\t %.6f \t%.f\t%s\n", fineLevel, memcpy_h2d, memcpy_d2h, total, BATCH[z] / (total / 1000), "Fine " + fineLevel);
#ifdef WRITEFILE
		fprintf(fpt, "F%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", fineLevel, BATCH[z], (size * 2e-6) / total, total, (cpu_t / total), ((size * 2e-6) / total) * 8, memcpy_h2d, elapsed, (cpu_t / elapsed), BATCH[z] / (total / 1000), (BATCH[z] / (total / 1000)) / (BATCH[z] / (cpu_t / 1000)));
#endif

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
		printf("\n======================================================================================================================================================\n");
	}
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();
	return 0;
}
