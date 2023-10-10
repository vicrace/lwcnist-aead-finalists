#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> 
#include <Windows.h>
#include <time.h>
#include "params.h"
#include "permutations.h"
#include "word.h"
#include "operations.h"
#include "ascon.h"

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

__global__ void crypto_aead_encrypt_gpu(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {
	(void)nsec;

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

	uint32_t tid = threadIdx.x;	uint32_t bid = blockIdx.x;
	uint32_t idx_im = bid * blockDim.x * mlen + tid * mlen;								// message
	uint32_t idx_ia = bid * blockDim.x * adlen + tid * adlen;							// AD
	uint32_t idx_nk = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES;		// key and nonce read only 16
	uint32_t idx_out = bid * blockDim.x * (*clen) + tid * (*clen);						// cipher text length

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

//GPU GlobalMem - read in col and write in row - transpose col
__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {
	(void)nsec;

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

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

	/* load key and nonce */
	const uint64_t K0 = LOADBYTESG(k + tko, 8);
	const uint64_t K1 = LOADBYTESG(k + 8 + tko, 8);
	const uint64_t N0 = LOADBYTESG(npub + tko, 8);
	const uint64_t N1 = LOADBYTESG(npub + 8 + tko, 8);

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
			s.x0 ^= LOADBYTESG(ad + tao, 8);
			P6G(&s);
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x0 ^= LOADBYTESG(ad + tao, adlen);
		s.x0 ^= PAD(adlen);
		P6G(&s);
	}
	/* domain separation */
	s.x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		s.x0 ^= LOADBYTESG(m + tmo, 8);
		STOREBYTESG(c + tci, s.x0, 8);
		P6G(&s);
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	s.x0 ^= LOADBYTESG(m + tmo, mlen);
	STOREBYTESG(c + tci, s.x0, mlen);
	s.x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	s.x1 ^= K0;
	s.x2 ^= K1;
	P12G(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	/* set tag */
	STOREBYTESG(c + tci, s.x3, 8);
	STOREBYTESG(c + tci + 8, s.x4, 8);
}


//Optimised GPU transpose version
__global__ void crypto_aead_encrypt_gpu_global_Op_Trans(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {
	(void)nsec;

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

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

	/* load key and nonce */
	const uint64_t K0 = LOADBYTESG(k + tko, 8);
	const uint64_t K1 = LOADBYTESG(k + 8 + tko, 8);
	const uint64_t N0 = LOADBYTESG(npub + tko, 8);
	const uint64_t N1 = LOADBYTESG(npub + 8 + tko, 8);

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
			x0 ^= LOADBYTESG(ad + tao, 8);
			P6_GO;
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		x0 ^= LOADBYTESG(ad + tao, adlen);
		x0 ^= PAD(adlen);
		P6_GO;
	}
	/* domain separation */
	x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		x0 ^= LOADBYTESG(m + tmo, 8);
		STOREBYTESG(c + tci, x0, 8);
		P6_GO;
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	x0 ^= LOADBYTESG(m + tmo, mlen);
	STOREBYTESG(c + tci, x0, mlen);
	x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	x1 ^= K0;
	x2 ^= K1;
	P12_GO;
	x3 ^= K0;
	x4 ^= K1;

	/* set tag */
	STOREBYTESG(c + tci, x3, 8);
	STOREBYTESG(c + tci + 8, x4, 8);
}

//GPU GlobalMem - transpose Col in Host & Unroll 4
__inline__ __device__ void encrypt_unroll4(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k, uint32_t tko, uint32_t tao, uint32_t tmo, uint32_t tci) {

	const uint64_t K0 = LOADBYTESG(k + tko, 8);
	const uint64_t K1 = LOADBYTESG(k + 8 + tko, 8);
	const uint64_t N0 = LOADBYTESG(npub + tko, 8);
	const uint64_t N1 = LOADBYTESG(npub + 8 + tko, 8);

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
			s.x0 ^= LOADBYTESG(ad + tao, 8);
			P6G(&s);
			ad += ASCON_128_RATE;
			adlen -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x0 ^= LOADBYTESG(ad + tao, adlen);
		s.x0 ^= PAD(adlen);
		P6G(&s);
	}
	/* domain separation */
	s.x4 ^= 1;

	/* full plaintext blocks */
	while (mlen >= ASCON_128_RATE) {
		s.x0 ^= LOADBYTESG(m + tmo, 8);
		STOREBYTESG(c + tci, s.x0, 8);
		P6G(&s);
		m += ASCON_128_RATE;
		c += ASCON_128_RATE;
		mlen -= ASCON_128_RATE;
	}
	/* final plaintext block */
	s.x0 ^= LOADBYTESG(m + tmo, mlen);
	STOREBYTESG(c + tci, s.x0, mlen);
	s.x0 ^= PAD(mlen);
	c += mlen;

	/* finalize */
	s.x1 ^= K0;
	s.x2 ^= K1;
	P12G(&s);
	s.x3 ^= K0;
	s.x4 ^= K1;

	/* set tag */
	STOREBYTESG(c + tci, s.x3, 8);
	STOREBYTESG(c + tci + 8, s.x4, 8);
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	/* set ciphertext size */
	*clen = mlen + CRYPTO_ABYTES;

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

	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko, tao, tmo, tci);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + blockDim.x, tao + blockDim.x, tmo + blockDim.x, tci + blockDim.x);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + 2 * blockDim.x, tao + 2 * blockDim.x, tmo + 2 * blockDim.x, tci + 2 * blockDim.x);
	encrypt_unroll4(c, clen, mout, mlen, aout, adlen, nsec, nout, kout, tko + 3 * blockDim.x, tao + 3 * blockDim.x, tmo + 3 * blockDim.x, tci + 3 * blockDim.x);
}

int main()
{
	uint8_t* nonce, * key, * msg, * ad, * ct, * tag;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen = MAX_CIPHER_LENGTH;	// cipher length
	int result = 0;

#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Ascon_Concurent.csv", "w");
	fprintf(fpt, "Version, Dimension, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	//Memory allocation - HOST
	cudaMallocHost((void**)& key, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& nonce, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMallocHost((void**)& msg, BATCH * mlen * sizeof(uint8_t));
	cudaMallocHost((void**)& ad, BATCH * alen * sizeof(uint8_t));
	cudaMallocHost((void**)& ct, BATCH * clen * sizeof(uint8_t));
	cudaMallocHost((void**)& tag, BATCH * clen * sizeof(uint8_t));

	//Initialise key, nonce, message and additional data
	init_buffer('k', key, CRYPTO_KEYBYTES);
	init_buffer('n', nonce, CRYPTO_NPUBBYTES);
	init_buffer('m', msg, mlen);
	init_buffer('a', ad, alen);

	//CPU implementation
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&t1);
	for (int i = 0; i < BATCH; i++) {
		result |= crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen), alen, 0,
			OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
	}
	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	//Print Time
	printf("Version\tCKernel\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");
#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host Op", 0, 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Host \tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));

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
	cudaMallocHost((void**)& h_c, BATCH * clen * sizeof(uint8_t));
	cudaMalloc((void**)& d_c, BATCH * clen * sizeof(uint8_t));
	cudaMalloc((void**)& d_n, BATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t));
	cudaMalloc((void**)& d_k, BATCH * CRYPTO_KEYBYTES * sizeof(uint8_t));
	cudaMalloc((void**)& d_m, BATCH * (uint64_t)mlen * sizeof(uint8_t));
	cudaMalloc((void**)& d_a, BATCH * (uint64_t)alen * sizeof(uint8_t));
	cudaMallocHost((void**)& d_clen, sizeof(uint64_t));
	*d_clen = MAX_CIPHER_LENGTH;

	void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*);
	size_t size = BATCH * (*d_clen) * sizeof(uint8_t);

	cudaStream_t GPUs2[2], GPUs4[4], GPUs5[5];
	cudaStream_t * GPUstreams;

	for (int z = 2; z <= NSTREAM_SIZE; z++) {

		if (z != 3) {
			switch (z) {
			case 2: {GPUstreams = GPUs2; break; }
			case 4: {GPUstreams = GPUs4; break; }
			case 5: {GPUstreams = GPUs5; break; }
			}

			for (int a = 0; a < z; a++) {	//1 streams 8 bits
				CHECK(cudaStreamCreate(&GPUstreams[a]));
			}

			//Determine data size
			int iBATCH = BATCH / z;
			size_t iKeysize = iBATCH * CRYPTO_KEYBYTES * sizeof(uint8_t);
			size_t iNoncesize = iBATCH * CRYPTO_NPUBBYTES * sizeof(uint8_t);
			size_t iMsgsize = iBATCH * (uint64_t)mlen * sizeof(uint8_t);
			size_t iAdsize = iBATCH * (uint64_t)alen * sizeof(uint8_t);
			size_t iCsize = iBATCH * (*d_clen) * sizeof(uint8_t);
			float memcpy_h2d;

			for (int i = 64; i < 1025; i *= 2) {

				//only thread 48 and above is executed since cipher have max 48 bytes to write.

				float elapsed, memcpy_d2h, total;

				for (int a = 1; a <= 4; a++) {
					if (a == 1) {
						cudaEventRecord(start, 0);
						for (int i = 0; i < z; ++i)
						{
							int ioffset = i * iBATCH;
							cudaMemcpyAsync(&d_n[ioffset * CRYPTO_NPUBBYTES], &nonce[ioffset * CRYPTO_NPUBBYTES], iNoncesize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_k[ioffset * CRYPTO_KEYBYTES], &key[ioffset * CRYPTO_KEYBYTES], iKeysize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_m[ioffset * mlen], &msg[ioffset * mlen], iMsgsize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_a[ioffset * alen], &ad[ioffset * alen], iAdsize, cudaMemcpyHostToDevice, GPUstreams[i]);
						}
						cudaEventRecord(stop, 0);
						cudaEventSynchronize(stop);
						memcpy_h2d = 0.0f;
						cudaEventElapsedTime(&memcpy_h2d, start, stop);
					}
					else if (a == 2) {
						cudaEventRecord(start, 0);
						for (int i = 0; i < z; ++i)
						{
							int ioffset = i * iBATCH;
							cudaMemcpyAsync(&d_n[ioffset * CRYPTO_NPUBBYTES], &nonce_out[ioffset * CRYPTO_NPUBBYTES], iNoncesize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_k[ioffset * CRYPTO_KEYBYTES], &key_out[ioffset * CRYPTO_KEYBYTES], iKeysize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_m[ioffset * mlen], &msg_out[ioffset * mlen], iMsgsize, cudaMemcpyHostToDevice, GPUstreams[i]);
							cudaMemcpyAsync(&d_a[ioffset * alen], &ad_out[ioffset * alen], iAdsize, cudaMemcpyHostToDevice, GPUstreams[i]);
						}
						cudaEventRecord(stop, 0);
						cudaEventSynchronize(stop);
						memcpy_h2d = 0.0f;
						cudaEventElapsedTime(&memcpy_h2d, start, stop);
					}

					//Configuration.
					dim3 threads(i);
					dim3 blocks(iBATCH / i);		

					if (a > 1) {
						threads.y = i;
						blocks.x = (iBATCH / (threads.x * threads.y));
						blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
					}

					//Determine Kernel Type.
					kernel = ((a == 1) ? &crypto_aead_encrypt_gpu : ((a == 2) ? &crypto_aead_encrypt_gpu_rcwr_GpuTranspose : ((a == 3) ? &crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4 :
						&crypto_aead_encrypt_gpu_global_Op_Trans)));
					char* kernelName = ((a == 1) ? "GPU Unoptimised" : ((a == 2) ? "GPU Tran" : ((a == 3) ? "GPU TransU4" : "GPU OpTrans ")));

					//Kernel execution
					memset(h_c, 0, BATCH * clen * sizeof(uint8_t));
					cudaEventRecord(start);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						kernel << <blocks, threads, 0, GPUstreams[i] >> > (&d_c[ioffset * clen], d_clen, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
							&d_n[ioffset * CRYPTO_NPUBBYTES], &d_k[ioffset * CRYPTO_KEYBYTES]);
					}
					cudaEventRecord(stop);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&elapsed, start, stop);

					//Memory Copy from D2H
					cudaEventRecord(start, 0);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						cudaMemcpyAsync(&h_c[ioffset * clen], &d_c[ioffset * clen], iCsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
					}
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&memcpy_d2h, start, stop);

#ifdef CHECKRESULT
					checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);
#endif

					double Ttime = 0;
					if (a < 2)
						total = memcpy_h2d + elapsed + memcpy_d2h;
					else {
						total = memcpy_h2d + trans + elapsed + memcpy_d2h;
						Ttime = trans;
					}

					printf("%s\t %d\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t%.f\n", kernelName, z, threads.x, memcpy_h2d,
						memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));

#ifdef WRITEFILE
					fprintf(fpt, "%s,%d, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, z, threads.x, total,
						memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif

				}
				printf("\n");

			}
			printf("\n======================================================================================================================================================\n");

			for (int i = 0; i < z; i++)
				CHECK(cudaStreamDestroy(GPUstreams[i]));
		}
	}

	//Free memory
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
	cudaDeviceReset();
	return 0;
}