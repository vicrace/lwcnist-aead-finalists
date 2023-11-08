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

		if ((dlen == 0) && (mlen == 0)) {
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

		if (dlen > 0) {
			absorb(state, A, dlen, C0, R);
		}

		if (mlen > 0) {
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
	const uint8_t * key,   // 16 -bytes secret key
	const uint8_t * nonce, // 16 -bytes public message nonce
	const uint8_t * data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t * txt,   // N -bytes plain text | N >= 0
	uint8_t * enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t * tag          // 16 -bytes authentication tag
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
	const uint8_t * key,   // 16 -bytes secret key
	const uint8_t * nonce, // 16 -bytes public message nonce
	const uint8_t * data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t * txt,   // N -bytes plain text | N >= 0
	uint8_t * enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t * tag          // 16 -bytes authentication tag
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


__global__ void crypto_aead_encrypt_gpu_global_Trans(
	const uint8_t * key,   // 16 -bytes secret key
	const uint8_t * nonce, // 16 -bytes public message nonce
	const uint8_t * data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t * txt,   // N -bytes plain text | N >= 0
	uint8_t * enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t * tag          // 16 -bytes authentication tag
) {
	if (check_rateG(R)) {

		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * dlen + threadIdx.x * dlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * dlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH + threadIdx.x * MAX_CIPHER_LENGTH;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t ttix = blockDim.x * blockIdx.x * TAG_LEN + threadIdx.x * TAG_LEN;				//for tag
		uint32_t ttiy = blockDim.x * blockIdx.y * TAG_LEN + (threadIdx.y * (blockDim.x * blockDim.x));

		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * dlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH + tcix; // access in row  - cipher
		uint32_t tt = tciy * TAG_LEN + ttix; // access in row  - cipher

		__syncthreads();

		uint8_t* C = enc + tc;
		uint8_t* T = tag + tt;
		uint8_t* M = const_cast<uint8_t*>(txt) + tm;
		uint8_t* A = const_cast<uint8_t*>(data) + ta;
		uint8_t* N = const_cast<uint8_t*>(nonce) + tn;
		uint8_t* K = const_cast<uint8_t*>(key) + tk;

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


__global__ void crypto_aead_encrypt_gpu_global_Op_Trans(
	const uint8_t * key,   // 16 -bytes secret key
	const uint8_t * nonce, // 16 -bytes public message nonce
	const uint8_t * data,  // N -bytes associated data | N >= 0
	const size_t dlen,                     // len(data) >= 0
	const uint8_t * txt,   // N -bytes plain text | N >= 0
	uint8_t * enc,         // N -bytes cipher text | N >= 0
	const size_t mlen,                     // len(txt) = len(enc) >= 0
	uint8_t * tag          // 16 -bytes authentication tag
) {
	if (check_rateG(R)) {

		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x * CRYPTO_KEYBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.y * CRYPTO_KEYBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x * CRYPTO_NPUBBYTES;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.x * mlen;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.y * mlen + (threadIdx.y * (blockDim.x * blockDim.x)); // * 2
		uint32_t taix = blockDim.x * blockIdx.x * dlen + threadIdx.x * dlen;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.y * dlen + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t tcix = blockDim.x * blockIdx.x * MAX_CIPHER_LENGTH + threadIdx.x * MAX_CIPHER_LENGTH;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.y * MAX_CIPHER_LENGTH + (threadIdx.y * (blockDim.x * blockDim.x));
		uint32_t ttix = blockDim.x * blockIdx.x * TAG_LEN + threadIdx.x * TAG_LEN;				//for tag
		uint32_t ttiy = blockDim.x * blockIdx.y * TAG_LEN + (threadIdx.y * (blockDim.x * blockDim.x));

		uint32_t tk = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key 
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tm = tmiy * mlen + tmix; // access in rows - message 
		uint32_t ta = taiy * dlen + taix; // access in columns - ad 
		uint32_t tc = tciy * MAX_CIPHER_LENGTH + tcix; // access in row  - cipher
		uint32_t tt = tciy * TAG_LEN + ttix; // access in row  - cipher


		uint8_t* C = enc + tc;
		uint8_t* T = tag + tt;
		uint8_t* M = const_cast<uint8_t*>(txt) + tm;
		uint8_t* A = const_cast<uint8_t*>(data) + ta;
		uint8_t* N = const_cast<uint8_t*>(nonce) + tn;
		uint8_t* K = const_cast<uint8_t*>(key) + tk;

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
	//FILE writing
	FILE* fpt;
	fpt = fopen("Photon_8x4_CA.csv", "w");
	fprintf(fpt, "Version, Configuration, Latency, MemcpyH2D, transpose, kerneltime, MemcpyD2H, AEAD/s, AEAD/s exclude transpose \n");

	//Host variable
	uint8_t* nonce, * key, * msg, * ad, * ct, * tag;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen = MLEN;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;

	//Memory Allocation - HOST
	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ct, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMallocHost((void**)& tag, BATCH * TAG_LEN * sizeof(uint8_t));

	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {

		int result = crypto_aead_encrypt(OFFSET(key, i, CRYPTO_KEYBYTES), OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(ad, i, alen),
			MAX_ASSOCIATED_DATA_LENGTH, OFFSET(msg, i, mlen), OFFSET(ct, i, clen), MAX_MESSAGE_LENGTH, OFFSET(tag, i, TAG_LEN));
	}
	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
	//Print Host Time
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
	printf("Version\t\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");
	printf("Host \t\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));


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


	uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c, *h_t, *d_t;
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
	cudaMalloc((void**)& d_t, BATCH * (uint64_t)TAG_LEN * sizeof(uint8_t));				//Message
	cudaMalloc((void**)& h_t, BATCH * (uint64_t)TAG_LEN * sizeof(uint8_t));				//Additional Data
	cudaMallocHost((void**)& d_clen, sizeof(uint64_t));

	//Memory initialisation
	memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
	cudaMemset(d_n, 0, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMemset(d_k, 0, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMemset(d_m, 0, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMemset(d_a, 0, BATCH * (uint64_t)alen * sizeof(uint8_t));
	cudaMemset(d_t, 0, BATCH * (uint64_t)TAG_LEN * sizeof(uint8_t));
	cudaMemset(d_t, 0, BATCH * (uint64_t)TAG_LEN * sizeof(uint8_t));
	*d_clen = MAX_CIPHER_LENGTH;

	//Memory Copy from H2D
	cudaEventRecord(start, 0);
	CHECK(cudaMemcpy(d_n, nonce_out, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
	CHECK(cudaMemcpy(d_k, key_out, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice));
	CHECK(cudaMemcpy(d_m, msg_out, BATCH * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice));
	CHECK(cudaMemcpy(d_a, ad_out, BATCH * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice));
	cudaEventRecord(stop, 0);
	cudaEventSynchronize(stop);
	float memcpy_h2d = 0.0f;
	cudaEventElapsedTime(&memcpy_h2d, start, stop);

	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

	for (int i = 64; i < 1025; i *= 2) {

		float elapsed, memcpy_d2h, total;

		dim3 threads(i);
		dim3 blocks(ceil((double)BATCH / (double)i));		//for unoptimised
		threads.y = i;
		double temp = (double)BATCH / ((double)threads.x * (double)threads.y);
		blocks.x = (temp < 1) ? 1 : ceil(temp); // at least 1 block

		//Ref Trans
		memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaEventRecord(start, 0);
		crypto_aead_encrypt_gpu_global_Trans << <blocks, threads >> > (d_k, d_n, d_a, MAX_ASSOCIATED_DATA_LENGTH, d_m, d_c, MAX_MESSAGE_LENGTH, d_t);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		elapsed = 0;
		cudaEventElapsedTime(&elapsed, start, stop);


		//Memory Copy from D2H
		cudaEventRecord(start, 0);
		cudaMemcpy(h_c, d_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
		cudaMemcpy(h_t, d_t, BATCH * TAG_LEN * sizeof(uint8_t), cudaMemcpyDeviceToHost);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		memcpy_d2h = 0;
		cudaEventElapsedTime(&memcpy_d2h, start, stop);

		total = memcpy_h2d + trans + elapsed + memcpy_d2h;

		printf("%s\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t%.f\n", "Ref Trans", threads.x, memcpy_h2d,
			memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - trans) / 1000));

		fprintf(fpt, "%s, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", "Ref Trans", threads.x, total,
			memcpy_h2d, trans, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - trans) / 1000));

		//Op Trans
		memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaEventRecord(start, 0);
		crypto_aead_encrypt_gpu_global_Op_Trans << <blocks, threads >> > (d_k, d_n, d_a, MAX_ASSOCIATED_DATA_LENGTH, d_m, d_c, MAX_MESSAGE_LENGTH, d_t);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		elapsed = 0;
		cudaEventElapsedTime(&elapsed, start, stop);

		//Memory Copy from D2H
		cudaEventRecord(start, 0);
		cudaMemcpy(h_c, d_c, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
		cudaMemcpy(h_t, d_t, BATCH * TAG_LEN * sizeof(uint8_t), cudaMemcpyDeviceToHost);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		memcpy_d2h = 0;
		cudaEventElapsedTime(&memcpy_d2h, start, stop);

		total = memcpy_h2d + trans + elapsed + memcpy_d2h;

		printf("%s\t %u \t\t%.6f\t%.6f \t%.6f  \t%.f \t\t%.f\n", "Op Trans", threads.x, memcpy_h2d,
			memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - trans) / 1000));

		fprintf(fpt, "%s, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", "Op Trans", threads.x, total,
			memcpy_h2d, trans, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - trans) / 1000));

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


	fclose(fpt);
	cudaDeviceReset();
	return 0;
}
