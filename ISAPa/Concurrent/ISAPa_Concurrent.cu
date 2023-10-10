
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "ISAP.h"
#include "params.h"
#include "operations.h"

//Reference : opt_64 version
int crypto_aead_encrypt(
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

__global__ void crypto_aead_encrypt_gpu_global_64Op(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
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

__global__ void crypto_aead_encrypt_gpu_global_32Op(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
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
			}
		}
	}

	// Generate tag
	uint8_t* tag = C + mlen;
	isap_mac_O32G_Op(K, N, A, adlen, C, mlen, tag);
	//}
}

__global__ void crypto_aead_encrypt_gpu_64RefTrans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	(void)nsec;
	*clen = mlen + CRYPTO_ABYTES;

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
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
		uint8_t* kout = const_cast<unsigned char*>(k + blockIdx.x * blockDim.x);
		uint8_t * nout = const_cast<unsigned char*>(npub + blockIdx.x * blockDim.x);
		uint8_t * mout = const_cast<unsigned char*>(m + blockIdx.x * blockDim.x);
		uint8_t * aout = const_cast<unsigned char*>(ad + blockIdx.x * blockDim.x);

		kout[tko] = k[tki]; // transpose from row to col for key
		nout[tko] = npub[tki]; //for nonce
		mout[tmo] = m[tmi]; //for message
		aout[tao] = ad[tai]; //for additional data

		__syncthreads();

		uint8_t * C = c + tci;
		uint8_t * M = mout + tmo;
		uint8_t * A = aout + tao;
		uint8_t * N = nout + tko;
		uint8_t * K = kout + tko;


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

__global__ void crypto_aead_encrypt_gpu_64Op_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k)
{
	(void)nsec;
	*clen = mlen + CRYPTO_ABYTES;

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
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
		uint8_t* kout = const_cast<unsigned char*>(k + blockIdx.x * blockDim.x);
		uint8_t * nout = const_cast<unsigned char*>(npub + blockIdx.x * blockDim.x);
		uint8_t * mout = const_cast<unsigned char*>(m + blockIdx.x * blockDim.x);
		uint8_t * aout = const_cast<unsigned char*>(ad + blockIdx.x * blockDim.x);

		kout[tko] = k[tki]; // transpose from row to col for key
		nout[tko] = npub[tki]; //for nonce
		mout[tmo] = m[tmi]; //for message
		aout[tao] = ad[tai]; //for additional data

		__syncthreads();

		uint8_t * C = c + tci;
		uint8_t * M = mout + tmo;
		uint8_t * A = aout + tao;
		uint8_t * N = nout + tko;
		uint8_t * K = kout + tko;

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

__global__ void crypto_aead_encrypt_gpu_global_32Op_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
{
	int tid = threadIdx.x, bid = blockIdx.x;
	uint32_t offset_msg = bid * blockDim.x * mlen + (tid * mlen);			// message
	uint32_t offset_ad = bid * blockDim.x * adlen + (tid * adlen);			// AD
	uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + (tid * CRYPTO_KEYBYTES); //key and nonce read only 16
	uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + (tid * CRYPTO_NPUBBYTES); //key and nonce read only 16
	uint32_t offset_ct = bid * blockDim.x * (MAX_CIPHER_LENGTH)+(tid * (MAX_CIPHER_LENGTH));	//instead of crypto_abytes

	(void)nsec;
	*clen = mlen + ISAP_TAG_SZ;

	if ((threadIdx.y * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tni = tniy * CRYPTO_NPUBBYTES + tnix; // access in rows - key & nonce
		uint32_t tno = tnix * CRYPTO_NPUBBYTES + tniy; // access in columns - key & nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		const uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		const uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		const uint8_t* N = const_cast<uint8_t*>(npub) + tno;
		const uint8_t* K = const_cast<uint8_t*>(k) + tko;

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
				}
			}
		}

		// Generate tag
		uint8_t* tag = C + mlen;
		isap_mac_O32G_Op(K, N, A, adlen, C, mlen, tag);
	}
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("ISAP_Concurent_raw.csv", "w");
	fprintf(fpt, "Version, Dimension, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	printf("\nSize Implementation : %d\n", BATCH);

	uint8_t* nonce, * key, * msg, * ad, * ct, * msg2;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen = MAX_CIPHER_LENGTH;	// cipher length
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1, t2;
	double cpu_t = 0;

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
		int result = crypto_aead_encrypt(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
			alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));
#ifdef PRINTC
		print('c', ct + (i * clen), clen);
#endif
	}

	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

	//Print Time
	printf("Version\t\tCKernel\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");
#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host Op", 0, 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Host \t\tSerial\t\t\t%.6f\t%.6f\t%.6f\t%.f\t\t\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));

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
			size_t iCsize = iBATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t);

			for (int i = 64; i < 1025; i *= 2) {


				float memcpy_h2d, elapsed, memcpy_d2h, total;

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
					double temp = (double)iBATCH / (double)i;
					dim3 blocks(ceil(temp));		

					if (a > 1) {
						threads.y = i;
						temp = (double)iBATCH / ((double)threads.x * (double)threads.y);
						blocks.x = ceil(temp);
						blocks.x = (blocks.x < 1) ? 1 : blocks.x; // at least 1 block
					}

					kernel = ((a == 1) ? &crypto_aead_encrypt_gpu_global_64Op : ((a == 2) ? &crypto_aead_encrypt_gpu_64RefTrans :
						((a == 3) ? &crypto_aead_encrypt_gpu_64Op_Trans : &crypto_aead_encrypt_gpu_global_32Op_Trans)));
					char* kernelName = ((a == 1) ? "GPU 64Op      " :  ((a==2)? "64Ref Trans  " : ((a == 3) ? "64Op Trans  " : "32Op Trans")));

					//Kernel execution
					memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
					cudaEventRecord(start);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						kernel << <blocks, threads, 0, GPUstreams[i] >> > (&d_c[ioffset * MAX_CIPHER_LENGTH], d_clen, &d_m[ioffset * mlen], mlen, &d_a[ioffset * alen], alen, 0,
							&d_n[ioffset * CRYPTO_NPUBBYTES], &d_k[ioffset * CRYPTO_KEYBYTES]);
					}
					cudaEventRecord(stop);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&elapsed, start, stop);

					//Memory Copy from D2H
					cudaEventRecord(start, 0);
					for (int i = 0; i < z; ++i) {
						int ioffset = i * iBATCH;
						cudaMemcpyAsync(&h_c[ioffset * MAX_CIPHER_LENGTH], &d_c[ioffset * MAX_CIPHER_LENGTH], iCsize, cudaMemcpyDeviceToHost, GPUstreams[i]);
					}
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					cudaEventElapsedTime(&memcpy_d2h, start, stop);

					checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);

					double Ttime = 0;
					if (a < 2)
						total = memcpy_h2d + elapsed + memcpy_d2h;
					else {
						total = memcpy_h2d + trans + elapsed + memcpy_d2h;
						Ttime = trans;
					}

					printf("%s\t %d\t %u \t\t%.6f\t%.6f \t%.6f  \t%.f \t\t%.f\n", kernelName, z, threads.x, memcpy_h2d,
						memcpy_d2h, total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#ifdef WRITEFILE
					fprintf(fpt, "%s,%d, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, z, threads.x, total,
						memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif
				}

			}

			printf("\n=======================================================================================================================================\n");
			for (int i = 0; i < z; i++)
				cudaStreamDestroy(GPUstreams[i]);
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
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();

}
