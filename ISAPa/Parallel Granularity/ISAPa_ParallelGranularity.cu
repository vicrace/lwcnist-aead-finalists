
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include "ISAP.h"
#include "params.h"
#include "operations.h"

//Reference : opt_64 version
int crypto_aead_encrypt_O64(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
) {
	(void)nsec;

	// Ciphertext length is mlen + tag length
	*clen = mlen + CRYPTO_ABYTES;

	if (mlen > 0) {
		u8 state[ISAP_STATE_SZ];

		// Init state
		u64* state64 = (u64*)state;
		u64* npub64 = (u64*)npub;
		isap_rk(k, ISAP_IV3, npub, CRYPTO_NPUBBYTES, state, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
		u64 x0, x1, x2, x3, x4;
		u64 t0, t1, t2, t3, t4;
		t0 = t1 = t2 = t3 = t4 = 0;
		x0 = U64BIG(state64[0]);
		x1 = U64BIG(state64[1]);
		x2 = U64BIG(state64[2]);
		x3 = U64BIG(npub64[0]);
		x4 = U64BIG(npub64[1]);
		P12(R);

		// Squeeze key stream
		u64 rem_bytes = mlen;
		u64 * m64 = (u64*)m;
		u64 * c64 = (u64*)c;
		u32 idx64 = 0;
		while (1) {
			if (rem_bytes > ISAP_rH_SZ) {
				// Squeeze full lane
				c64[idx64] = U64BIG(x0) ^ m64[idx64];
				idx64++;
				P12(R);
				rem_bytes -= ISAP_rH_SZ;
			}
			else if (rem_bytes == ISAP_rH_SZ) {
				// Squeeze full lane and stop
				c64[idx64] = U64BIG(x0) ^ m64[idx64];
				break;
			}
			else {
				// Squeeze partial lane and stop
				u64 lane64 = U64BIG(x0);
				u8* lane8 = (u8*)& lane64;
				u32 idx8 = idx64 * 8;
				for (u32 i = 0; i < rem_bytes; i++) {
					c[idx8] = lane8[i] ^ m[idx8];
					idx8++;
				}
				break;
			}
		}
	}

	// Generate tag
	unsigned char* tag = c + mlen;
	isap_mac(k, npub, ad, adlen, c, mlen, tag);

	return 0;
}

int crypto_aead_encrypt_O32(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	(void)nsec;

	// Ciphertext length is mlen + tag length
	*clen = mlen + ISAP_TAG_SZ;

	// Encrypt plaintext
	if (mlen > 0) {
		// Derive Ke
		u8 ke[ISAP_STATE_SZ - CRYPTO_NPUBBYTES];
		isap_rk_O32(k, ISAP_IV3, npub, ke, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);

		// State and temporary variables
		u32_2 x0, x1, x2, x3, x4;
		u64 tmp0;

		// Init State
		x0.o = *(u32*)(ke + 0);
		x0.e = *(u32*)(ke + 4);
		x1.o = *(u32*)(ke + 8);
		x1.e = *(u32*)(ke + 12);
		x2.o = *(u32*)(ke + 16);
		x2.e = *(u32*)(ke + 20);
		to_bit_interleaving(&x3, U64BIG32(*(u64*)npub));
		to_bit_interleaving(&x4, U64BIG32(*(u64*)(npub + 8)));

		// Squeeze full lanes
		while (mlen >= 8)
		{
			P_sE;
			from_bit_interleaving(&tmp0, x0);
			*(u64*)c = *(u64*)m ^ U64BIG32(tmp0);
			mlen -= 8;
			m += ISAP_rH / 8;
			c += ISAP_rH / 8;
		}

		// Squeeze partial lane
		if (mlen > 0)
		{
			P_sE;
			from_bit_interleaving(&tmp0, x0);
			tmp0 = U64BIG32(tmp0);
			u8* tmp0_bytes = (u8*)& tmp0;
			for (u8 i = 0; i < mlen; i++)
			{
				*c = *m ^ tmp0_bytes[i];
				m += 1;
				c += 1;
			}
		}
	}

	// Generate tag
	unsigned char* tag = c + mlen;
	isap_mac_O32(k, npub, ad, adlen, c, mlen, tag);
	return 0;
}

__global__ void crypto_aead_encrypt_gpu_global_64Ref(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k,
	int Batch)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
	uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
	uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

	(void)nsec;

	if (blockDim.x * blockIdx.x + threadIdx.x < Batch) {
		// Ciphertext length is mlen + tag length
		*clen = mlen + CRYPTO_ABYTES;
		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<u8*>(m) + offset_msg;
		uint8_t* A = const_cast<u8*>(ad) + offset_ad;
		uint8_t* N = const_cast<u8*>(npub) + offset_nonce;
		uint8_t* K = const_cast<u8*>(k) + offset_key;

		if (mlen > 0) {
			u8 state[ISAP_STATE_SZ];

			// Init state
			u64* state64 = (u64*)state;
			u64* npub64 = (u64*)N;
			isap_rkG(K, ISAP_IV3G, N, CRYPTO_NPUBBYTES, state, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
			u64 x0, x1, x2, x3, x4;
			u64 t0, t1, t2, t3, t4;
			t0 = t1 = t2 = t3 = t4 = 0;
			x0 = U64BIG(state64[0]);
			x1 = U64BIG(state64[1]);
			x2 = U64BIG(state64[2]);
			x3 = U64BIG(npub64[0]);
			x4 = U64BIG(npub64[1]);
			P12(RG);

			// Squeeze key stream
			u64 rem_bytes = mlen;
			u64 * m64 = (u64*)M; //
			u64 * c64 = (u64*)C; //
			u32 idx64 = 0;
			while (1) {
				if (rem_bytes > ISAP_rH_SZ) {
					// Squeeze full lane
					c64[idx64] = U64BIG(x0) ^ m64[idx64];
					idx64++;
					P12(RG);
					rem_bytes -= ISAP_rH_SZ;
				}
				else if (rem_bytes == ISAP_rH_SZ) {
					// Squeeze full lane and stop
					c64[idx64] = U64BIG(x0) ^ m64[idx64];
					break;
				}
				else {
					// Squeeze partial lane and stop
					u64 lane64 = U64BIG(x0);
					u8* lane8 = (u8*)& lane64;
					u32 idx8 = idx64 * 8;

					for (u32 i = 0; i < rem_bytes; i++) {
						C[idx8] = lane8[i] ^ M[idx8];
						idx8++;
					}
					break;
				}
			}
		}

		// Generate tag
		unsigned char* tag = C + mlen;
		isap_macG(K, N, A, adlen, C, mlen, tag);
	}
}


//Op32 Ref
__global__ void crypto_aead_encrypt_gpu_global_32Ref(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k,
	int Batch)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
	uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
	uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

	(void)nsec;

	if (blockDim.x * blockIdx.x + threadIdx.x < Batch) {
		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<u8*>(m) + offset_msg;
		uint8_t* A = const_cast<u8*>(ad) + offset_ad;
		uint8_t* N = const_cast<u8*>(npub) + offset_nonce;
		uint8_t* K = const_cast<u8*>(k) + offset_key;

		// Ciphertext length is mlen + tag length
		*clen = mlen + ISAP_TAG_SZ;

		// Encrypt plaintext
		if (mlen > 0) {
			// Derive Ke
			u8 ke[ISAP_STATE_SZ - CRYPTO_NPUBBYTES];
			isap_rk_O32G(K, ISAP_IV3G, N, ke, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);

			// State and temporary variables
			u32_2 x0, x1, x2, x3, x4;
			u64 tmp0;

			// Init State
			x0.o = *(u32*)(ke + 0);
			x0.e = *(u32*)(ke + 4);
			x1.o = *(u32*)(ke + 8);
			x1.e = *(u32*)(ke + 12);
			x2.o = *(u32*)(ke + 16);
			x2.e = *(u32*)(ke + 20);
			to_bit_interleavingG(&x3, U64BIG32G(*(u64*)N));
			to_bit_interleavingG(&x4, U64BIG32G(*(u64*)(N + 8)));

			// Squeeze full lanes
			while (mlen >= 8)
			{
				P_sEG;
				from_bit_interleavingG(&tmp0, x0);
				*(u64*)C = *(u64*)M ^ U64BIG32G(tmp0);
				mlen -= 8;
				M += ISAP_rH / 8;
				C += ISAP_rH / 8;
			}

			// Squeeze partial lane
			if (mlen > 0)
			{
				P_sEG;
				from_bit_interleavingG(&tmp0, x0);
				tmp0 = U64BIG32G(tmp0);
				u8* tmp0_bytes = (u8*)& tmp0;
				for (u8 i = 0; i < mlen; i++)
				{
					*C = *M ^ tmp0_bytes[i];
					M += 1;
					C += 1;
				}
			}
		}

		// Generate tag
		uint8_t* tag = C + mlen;
		isap_mac_O32G(K, N, A, adlen, C, mlen, tag);
	}
}


//Op64 Optimised - unrolling loop
__global__ void crypto_aead_encrypt_gpu_global_64Op(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k,
	int Batch)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
	uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
	uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
	uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
	uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+tid * (MAX_CIPHER_LENGTH);	//instead of crypto_abytes

	(void)nsec;

	// Ciphertext length is mlen + tag length
	*clen = mlen + CRYPTO_ABYTES;

	if (blockIdx.x * blockDim.x + threadIdx.x) {
		uint8_t* C = c + offset_ct;
		uint8_t* M = const_cast<u8*>(m) + offset_msg;
		uint8_t* A = const_cast<u8*>(ad) + offset_ad;
		uint8_t* N = const_cast<u8*>(npub) + offset_nonce;
		uint8_t* K = const_cast<u8*>(k) + offset_key;

		if (mlen > 0) {
			__shared__ u8 state[ISAP_STATE_SZ];

			// Init state
			u64* state64 = (u64*)state;
			u64* npub64 = (u64*)N;

			u64 x0, x1, x2, x3, x4;
			u64 t0, t1, t2, t3, t4;
			t0 = t1 = t2 = t3 = t4 = 0;

			isap_rkGT(K, ISAP_IV3G, N, CRYPTO_NPUBBYTES, state, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
			x0 = U64BIG(state64[0]);
			x1 = U64BIG(state64[1]);
			x2 = U64BIG(state64[2]);
			x3 = U64BIG(npub64[0]);
			x4 = U64BIG(npub64[1]);
			P12G;

			// Squeeze key stream
			u64 rem_bytes = mlen;
			u64 * m64 = (u64*)M; //
			u64 * c64 = (u64*)C; //
			u32 idx64 = 0;
			while (1) {
				if (rem_bytes > ISAP_rH_SZ) {
					// Squeeze full lane
					c64[idx64] = U64BIG(x0) ^ m64[idx64];
					idx64++;
					P12G;
					rem_bytes -= ISAP_rH_SZ;
				}
				else if (rem_bytes == ISAP_rH_SZ) {
					// Squeeze full lane and stop
					c64[idx64] = U64BIG(x0) ^ m64[idx64];
					break;
				}
				else {
					// Squeeze partial lane and stop
					u64 lane64 = U64BIG(x0);
					u8* lane8 = (u8*)& lane64;
					u32 idx8 = idx64 * 8;

					for (u32 i = 0; i < rem_bytes; i += 4) {
						C[idx8] = lane8[i] ^ M[idx8];
						C[++idx8] = lane8[i + 1] ^ M[++idx8];
						C[++idx8] = lane8[i + 2] ^ M[++idx8];
						C[++idx8] = lane8[i + 3] ^ M[++idx8];
					}
					break;
				}
			}
		}

		// Generate tag
		unsigned char* tag = C + mlen;
		isap_macGT(K, N, A, adlen, C, mlen, tag);
	}
}


//Op32 Optimised - memory , unrolling
__global__ void crypto_aead_encrypt_gpu_global_32Op(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k,
	int Batch)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t offset_msg = bid * blockDim.x * mlen + (tid * mlen);			// message
	uint32_t offset_ad = bid * blockDim.x * adlen + (tid * adlen);			// AD
	uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + (tid * CRYPTO_KEYBYTES); //key and nonce read only 16
	uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + (tid * CRYPTO_NPUBBYTES); //key and nonce read only 16
	uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+(tid * (MAX_CIPHER_LENGTH));	//instead of crypto_abytes

	(void)nsec;

	//if (blockDim.x * blockIdx.x + threadIdx.x < Batch) {
	uint8_t* C = c + offset_ct;
	uint8_t* M = const_cast<u8*>(m) + offset_msg;
	uint8_t* A = const_cast<u8*>(ad) + offset_ad;
	uint8_t* N = const_cast<u8*>(npub) + offset_nonce;
	uint8_t* K = const_cast<u8*>(k) + offset_key;

	// Ciphertext length is mlen + tag length
	*clen = mlen + ISAP_TAG_SZ;

	// Encrypt plaintext
	if (mlen > 0) {
		// Derive Ke
		__shared__ u8 ke[ISAP_STATE_SZ - CRYPTO_NPUBBYTES];
		isap_rk_O32G_Op(K, ISAP_IV3G, N, ke, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);

		// State and temporary variables
		u32_2 x0, x1, x2, x3, x4;
		u64 tmp0;

		// Init State
		x0.o = *(u32*)(ke + 0);
		x0.e = *(u32*)(ke + 4);
		x1.o = *(u32*)(ke + 8);
		x1.e = *(u32*)(ke + 12);
		x2.o = *(u32*)(ke + 16);
		x2.e = *(u32*)(ke + 20);
		to_bit_interleavingG(&x3, U64BIG32G(*(u64*)N));
		to_bit_interleavingG(&x4, U64BIG32G(*(u64*)(N + 8)));

		// Squeeze full lanes
		while (mlen >= 8)
		{
			P_sEG_Op;
			from_bit_interleavingG(&tmp0, x0);
			*(u64*)C = *(u64*)M ^ U64BIG32G(tmp0);
			mlen -= 8;
			M += ISAP_rH / 8;
			C += ISAP_rH / 8;
		}

		// Squeeze partial lane
		if (mlen > 0)
		{
			P_sEG_Op;
			from_bit_interleavingG(&tmp0, x0);
			tmp0 = U64BIG32G(tmp0);
			u8* tmp0_bytes = (u8*)& tmp0;

			for (u8 i = 0; i < mlen; i++)
			{
				*C = *M ^ tmp0_bytes[i];
				M += 1;
				C += 1;

				////unroll 2
				//*C = *M ^ tmp0_bytes[i + 1];
				//M += 1;
				//C += 1;
			}
		}
	}

	// Generate tag
	uint8_t* tag = C + mlen;
	isap_mac_O32G_Op(K, N, A, adlen, C, mlen, tag);
	//}
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("ISAPa_PG.csv", "w");
	fprintf(fpt, "Version, Size, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Execution Time, Speed UP (Execution), AEAD/s\n");
#endif

	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000};

	for (int z = 0; z < BATCH_SIZE; z++) {
		uint8_t* nonce, * key, * msg, * ad, * ct, * ct32;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen = MAX_CIPHER_LENGTH, clen2 = MAX_CIPHER_LENGTH;	// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t64, cpu_t32;

		printf("\nSize Implementation : %d\n", BATCH[z]);

		cudaMallocHost((void**)& key, BATCH[z] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[z] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[z] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[z] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
		cudaMallocHost((void**)& ct32, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[z]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[z]);
		init_buffer('m', msg, mlen, BATCH[z]);
		init_buffer('a', ad, alen, BATCH[z]);

		//Op64
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {

			int result = crypto_aead_encrypt_O64(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));


#ifdef PRINTC
			print('c', ct + i * clen, clen);
#endif  // PRINTC

		}
		QueryPerformanceCounter(&t2);
		cpu_t64 = 0;
		cpu_t64 += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
		//Print Host Time
		printf("\nVersion \tLatency (ms)\tAEAD/s\n");
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host64", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t64, cpu_t64, 0.0, (((BATCH[z] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t64) * 8, 0.0, cpu_t64, 0.0, BATCH[z] / (cpu_t64 / 1000), 0.0);
#endif
		printf("\nHost64 Time :\t %.6f ms\t%.f\n", cpu_t64, BATCH[z] / (cpu_t64 / 1000));


		//Op32
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[z]; i++) {

			int result = crypto_aead_encrypt_O32(OFFSET(ct32, i, clen2), &clen2, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));


#ifdef PRINTC
			print('c', ct32 + i * clen2, clen2);
#endif  // PRINTC

		}
		QueryPerformanceCounter(&t2);
		cpu_t32 = 0;
		cpu_t32 += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
#ifdef WRITEFILE
		fprintf(fpt, "%s,%d, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.2f, %.2f\n", "Host32", BATCH[z], ((BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t)) * 1e-6) / cpu_t32, cpu_t32, 0.0, (((BATCH[z] * clen2 * sizeof(uint8_t)) * 1e-6) / cpu_t32) * 8, 0.0, cpu_t32, 0.0, BATCH[z] / (cpu_t32 / 1000), 0.0);
#endif
		printf("Host32 Time :\t %.6f ms\t%.f\n", cpu_t32, BATCH[z] / (cpu_t32 / 1000));

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
		crypto_aead_encrypt_gpu_global_64Ref << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_32Ref << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_64Op << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
		crypto_aead_encrypt_gpu_global_32Op << <BATCH[z] / 1, 1 >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);

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
			int blocks = ((BATCH[z] / i) < 1) ? 1 : (BATCH[z] / i);

			/////Optimized 64Op
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_64Op << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float kernel = 0.0f;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			float memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("GPU 64 Op", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t64, fpt, BATCH[z], "GPU 64 Op");
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t64, NULL, BATCH[z], "GPU 64 Op");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));



			//Op 64 Ref
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_64Ref << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h, kernel = 0;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("GPU 64 Ref", ct, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t64, fpt, BATCH[z], "GPU 64 Ref");
#else
			PrintTime(ct, h_c, &clen, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t64, NULL, BATCH[z], "GPU 64 Ref");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

			//Op 32 Optimised
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_32Op << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0.0f;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("GPU 32 Op", ct32, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct32, h_c, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t32, fpt, BATCH[z], "GPU 32 Op");
#else
			PrintTime(ct32, h_c, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t32, NULL, BATCH[z], "GPU 32 Op");
#endif
			memset(h_c, 0, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t));



			/////Op 32 Ref
			cudaEventRecord(start, 0);
			crypto_aead_encrypt_gpu_global_32Ref << <blocks, i >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[z]);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			kernel = 0.0f;
			cudaEventElapsedTime(&kernel, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH[z] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			memcpy_d2h = 0.0f;
			cudaEventElapsedTime(&memcpy_d2h, start, stop);
			checkResult("GPU 32 Ref", ct32, h_c, MAX_CIPHER_LENGTH, BATCH[z]);

#ifdef WRITEFILE
			PrintTime(ct32, h_c, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t32, fpt, BATCH[z], "GPU 32 Ref");
#else
			PrintTime(ct32, h_c, &clen2, i, memcyp_h2d, kernel, memcpy_d2h, cpu_t32, NULL, BATCH[z], "GPU 32 Ref");
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
		cudaFree(ct32);

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