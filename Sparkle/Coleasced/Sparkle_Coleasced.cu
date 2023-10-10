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
	const uint8_t * k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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

__global__ void crypto_aead_encrypt_gpu_global_OpRef(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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

__global__ void crypto_aead_encrypt_gpu_global_Op(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k)
{

	int tid = threadIdx.x, bid = blockIdx.x;

	if (bid * blockDim.x + tid < BATCH) {
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

__global__ void crypto_aead_encrypt_gpu_global_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key 
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * MAX_CIPHER_LENGTH + tcix; // access in row  - cipher

		uint8_t * C = c + tci;
		uint8_t * M = const_cast<unsigned char*>(m)+ tmo;
		uint8_t * A = const_cast<unsigned char*>(ad) + tao;
		uint8_t * N = const_cast<unsigned char*>(npub) + tno;
		uint8_t * K = const_cast<unsigned char*>(k) + tko;

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

__global__ void crypto_aead_encrypt_gpu_global_OpRef_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {


	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key 
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		uint8_t* M = const_cast<unsigned char*>(m) + tmo;
		uint8_t* A = const_cast<unsigned char*>(ad) + tao;
		uint8_t* N = const_cast<unsigned char*>(npub) + tno;
		uint8_t* K = const_cast<unsigned char*>(k) + tko;

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

__global__ void crypto_aead_encrypt_gpu_global_Op_Trans(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k) {

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key 
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		uint8_t* M = const_cast<unsigned char*>(m) + tmo;
		uint8_t* A = const_cast<unsigned char*>(ad) + tao;
		uint8_t* N = const_cast<unsigned char*>(npub) + tno;
		uint8_t* K = const_cast<unsigned char*>(k) + tko;

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
	fpt = fopen("Sparkle256_CA.csv", "w");
	fprintf(fpt, "Version, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	uint8_t* nonce, * key, * msg, * ad, * ct;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen = MAX_CIPHER_LENGTH;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;
	printf("Version\t\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");

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
#ifdef PRINT
		print('m', msg + (i * mlen), mlen);
		printf(" -> ");
		print('a', ad + (i * alen), alen);
		print('k', key + (i * CRYPTO_KEYBYTES), CRYPTO_KEYBYTES);
		printf(" ");
		print('n', nonce + (i * CRYPTO_NPUBBYTES), CRYPTO_NPUBBYTES);
		printf(" ");
#endif

		int result = crypto_aead_encrypt_Op(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}
	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Host \t\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t\t\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));



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

	//Warm Up Kernel
	crypto_aead_encrypt_gpu_global << <BATCH / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
	crypto_aead_encrypt_gpu_global_OpRef << <BATCH / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
	crypto_aead_encrypt_gpu_global_Op << <BATCH / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

	for (int i = 64; i < 1025; i *= 2) {

		float memcpy_h2d, elapsed, memcpy_d2h, total;

		for (int z = 1; z < 7; z++) {

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
			else if (z == 4) { // for coleasced
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
			dim3 blocks(ceil((double)BATCH / (double)i));	
			if (z > 3) {
				threads.y = i;
				double temp = (double)BATCH / ((double)threads.x * (double)threads.y);
				blocks.x = (temp < 1) ? 1 : ceil(temp); // at least 1 block
			}

			kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global : ((z == 2) ? &crypto_aead_encrypt_gpu_global_OpRef : ((z == 3) ? &crypto_aead_encrypt_gpu_global_Op :
				((z == 4) ? &crypto_aead_encrypt_gpu_global_Trans : ((z == 5) ? &crypto_aead_encrypt_gpu_global_OpRef_Trans : &crypto_aead_encrypt_gpu_global_Op_Trans)))));
			char* kernelName = ((z == 1) ? "GPU Ref    " : ((z == 2) ? "GPU Op Ref " : ((z == 3) ? "GPU Op   " :
				((z == 4) ? "GPU Ref Trans" : ((z == 5) ? "GPU OpRef Trans" : "GPU Op Trans")))));

			//Kernel execution
			memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaEventRecord(start, 0);
			kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			elapsed = 0.0f;
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);

			double Ttime = 0;
			if (z < 4)
				total = memcpy_h2d + elapsed + memcpy_d2h;
			else {
				total = memcpy_h2d + trans + elapsed + memcpy_d2h;
				Ttime = trans;
			}

			printf("%s\t %u \t\t%.6f\t%.6f\t%.6f\t%.f \t\t%.f\n", kernelName, threads.x, memcpy_h2d,
				memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));

#ifdef WRITEFILE
			fprintf(fpt, "%s, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, threads.x, total,
				memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif
		}
		printf("\n========================================================================================================================\n");


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
}
