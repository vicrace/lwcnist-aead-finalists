
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "operations.h"
#include "params.h"
#include "giftcofb.h"
#include "Giftcofb_Op.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	*clen = mlen + CRYPTO_ABYTES;

	unsigned char* M = const_cast<unsigned char*>(m);
	unsigned char* A = const_cast<unsigned char*>(ad);
	unsigned char* N = const_cast<unsigned char*>(npub);
	unsigned char* K = const_cast<unsigned char*>(k);
	unsigned char* C = const_cast<unsigned char*>(c);

	unsigned i;
	unsigned emptyA, emptyM;

	if (!COFB_ENCRYPT) {
		mlen -= CRYPTO_ABYTES;
	}

	emptyA = (adlen == 0) ? 1 : 0;
	emptyM = (mlen == 0) ? 1 : 0;

	/*Mask-Gen*/
	block Y, input;
	half_block offset;
	/*nonce is 128-bit*/
	for (i = 0; i < 16; i++)
		input[i] = N[i];

	giftb128(input, k, Y);
	for (i = 0; i < 8; i++)
		offset[i] = Y[i];


	/*Process AD*/
	/*non-empty A*/
/*full blocks*/
	while (adlen > 16) {
		/* X[i] = (A[i] + G(Y[i-1])) + offset */
		pho1(input, Y, A, 16);
		/* offset = 2*offset */
		double_half_block(offset, offset);
		xor_topbar_block(input, input, offset);
		/* Y[i] = E(X[i]) */
		giftb128(input, K, Y);

		A = A + 16;
		adlen -= 16;
	}

	/* last block */
	/* full block: offset = 3*offset */
	/* partial block: offset = 3^2*offset */
	triple_half_block(offset, offset);
	if ((adlen % 16 != 0) || (emptyA)) {
		triple_half_block(offset, offset);
	}

	if (emptyM) {
		/* empty M: offset = 3^2*offset */
		triple_half_block(offset, offset);
		triple_half_block(offset, offset);
	}

	/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
	pho1(input, Y, A, adlen);

	xor_topbar_block(input, input, offset);
	/* Y[a] = E(X[a]) */
	giftb128(input, K, Y);


	/* Process M */
	/* full blocks */
	while (mlen > 16) {
		double_half_block(offset, offset);
		/* C[i] = Y[i+a-1] + M[i]*/
		/* X[i] = M[i] + G(Y[i+a-1]) + offset */
		if (COFB_ENCRYPT) {
			pho(Y, M, input, C, 16);
		}
		else {
			phoprime(Y, M, input, C, 16);
		}

		xor_topbar_block(input, input, offset);
		/* Y[i] = E(X[i+a]) */
		giftb128(input, K, Y);

		M = M + 16;
		C = C + 16;
		mlen -= 16;
	}

	if (!emptyM) {
		/* full block: offset = 3*offset */
		/* empty data / partial block: offset = 3^2*offset */
		triple_half_block(offset, offset);
		if (mlen % 16 != 0) {
			triple_half_block(offset, offset);
		}
		/* last block */
		/* C[m] = Y[m+a-1] + M[m]*/
		/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
		if (COFB_ENCRYPT) {
			pho(Y, M, input, C, mlen);
			C += mlen;
		}
		else {
			phoprime(Y, M, input, C, mlen);
			M += mlen;
		}


		xor_topbar_block(input, input, offset);
		/* T = E(X[m+a]) */
		giftb128(input, K, Y);
	}

	memcpy(C, Y, CRYPTO_ABYTES);

	return 0;
}

__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
{
	*clen = mlen + CRYPTO_ABYTES;
	int tid = threadIdx.x, bid = blockIdx.x;

	if ((bid * blockDim.x + tid) < BATCH) {
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (*clen) + tid * (*clen);	//instead of crypto_abytes

		unsigned char* M = const_cast<unsigned char*>(m + offset_msg);
		unsigned char* A = const_cast<unsigned char*>(ad + offset_ad);
		unsigned char* N = const_cast<unsigned char*>(npub + offset_nonce);
		unsigned char* K = const_cast<unsigned char*>(k + offset_key);
		unsigned char* C = const_cast<unsigned char*>(c + offset_ct);

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__global__ void crypto_aead_encrypt_gpu_global_Op_Register(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
{
	(void)nsec;
	*clen = mlen + TAGBYTES;

	int tid = threadIdx.x, bid = blockIdx.x;

	if ((bid * blockDim.x + tid) < BATCH) {

		int tid = threadIdx.x, bid = blockIdx.x;
		uint32_t offset_msg = bid * blockDim.x * mlen + tid * mlen;			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + tid * adlen;			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + tid * CRYPTO_KEYBYTES; //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + tid * CRYPTO_NPUBBYTES; //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (*clen) + tid * (*clen);	//instead of crypto_abytes

		u8* M = const_cast<u8*>(m + offset_msg);
		u8 * A = const_cast<u8*>(ad + offset_ad);
		u8 * N = const_cast<u8*>(npub + offset_nonce);
		u8 * K = const_cast<u8*>(k + offset_key);
		u8 * C = const_cast<u8*>(c + offset_ct);

		u32 tmp0, tmp1, emptyA, emptyM;
		u32 offset[2], input[4], rkey[80];
		u8 Y[16];

		if (!COFB_ENCRYPT) {
			if (mlen < TAGBYTES)
				return;
			mlen -= TAGBYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		precompute_rkeysG_OpBased(rkey, K);
		giftb128G_NewOp(Y, N, rkey);
		offset[0] = ((u32*)Y)[0];
		offset[1] = ((u32*)Y)[1];

		while (adlen > BLOCKBYTES) {
			RHO1G_Op(input, (u32*)Y, (u32*)A, BLOCKBYTES);

			DOUBLE_HALF_BLOCK(offset);
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
			A += BLOCKBYTES;
			adlen -= BLOCKBYTES;
		}

		TRIPLE_HALF_BLOCK(offset);

		if ((adlen % BLOCKBYTES != 0) || (emptyA)) {
			TRIPLE_HALF_BLOCK(offset);
		}
		if (emptyM) {
			TRIPLE_HALF_BLOCK(offset);
			TRIPLE_HALF_BLOCK(offset);
		}

		RHO1G_Op(input, (u32*)Y, (u32*)A, adlen);
		XOR_TOP_BAR_BLOCK(input, offset);
		giftb128G_NewOp(Y, (u8*)input, rkey);

		while (mlen > BLOCKBYTES) {
			DOUBLE_HALF_BLOCK(offset);

			if (COFB_ENCRYPT)
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);
			else
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);

			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
			M += BLOCKBYTES;
			C += BLOCKBYTES;
			mlen -= BLOCKBYTES;
		}

		if (!emptyM) {
			TRIPLE_HALF_BLOCK(offset);

			if (mlen % BLOCKBYTES != 0) {
				TRIPLE_HALF_BLOCK(offset);
			}
			if (COFB_ENCRYPT) {
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, mlen);
				C += mlen;
			}
			else {
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, mlen);
				M += mlen;
			}
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
		}

		if (COFB_ENCRYPT) {
			memcpy(C, Y, TAGBYTES);
		}
	}
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GpuTranspose(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	*clen = mlen + CRYPTO_ABYTES;

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tko;

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__inline__ __device__ void encrypt_unroll4(uint8_t* c, uint64_t* clen, const uint8_t* m, uint64_t mlen, const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k, uint32_t tko, uint32_t tao, uint32_t tmo, uint32_t tci, uint32_t tn) {

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {

		uint8_t* C = c + tci;
		uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tko;

		unsigned i;
		unsigned emptyA, emptyM;

		if (!COFB_ENCRYPT) {
			mlen -= CRYPTO_ABYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		/*Mask-Gen*/
		block Y, input;
		half_block offset;
		/*nonce is 128-bit*/
		for (i = 0; i < 16; i++)
			input[i] = N[i];

		giftb128G(input, K, Y);
		for (i = 0; i < 8; i++)
			offset[i] = Y[i];


		/*Process AD*/
		/*non-empty A*/
	/*full blocks*/
		while (adlen > 16) {
			/* X[i] = (A[i] + G(Y[i-1])) + offset */
			pho1G(input, Y, A, 16);
			/* offset = 2*offset */
			double_half_blockG(offset, offset);
			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i]) */
			giftb128G(input, K, Y);

			A = A + 16;
			adlen -= 16;
		}

		/* last block */
		/* full block: offset = 3*offset */
		/* partial block: offset = 3^2*offset */
		triple_half_blockG(offset, offset);
		if ((adlen % 16 != 0) || (emptyA)) {
			triple_half_blockG(offset, offset);
		}

		if (emptyM) {
			/* empty M: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			triple_half_blockG(offset, offset);
		}

		/* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
		pho1G(input, Y, A, adlen);

		xor_topbar_blockG(input, input, offset);
		/* Y[a] = E(X[a]) */
		giftb128G(input, K, Y);


		/* Process M */
		/* full blocks */
		while (mlen > 16) {
			double_half_blockG(offset, offset);
			/* C[i] = Y[i+a-1] + M[i]*/
			/* X[i] = M[i] + G(Y[i+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, 16);
			}
			else {
				phoprimeG(Y, M, input, C, 16);
			}

			xor_topbar_blockG(input, input, offset);
			/* Y[i] = E(X[i+a]) */
			giftb128G(input, K, Y);

			M = M + 16;
			C = C + 16;
			mlen -= 16;
		}

		if (!emptyM) {
			/* full block: offset = 3*offset */
			/* empty data / partial block: offset = 3^2*offset */
			triple_half_blockG(offset, offset);
			if (mlen % 16 != 0) {
				triple_half_blockG(offset, offset);
			}
			/* last block */
			/* C[m] = Y[m+a-1] + M[m]*/
			/* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
			if (COFB_ENCRYPT) {
				phoG(Y, M, input, C, mlen);
				C += mlen;
			}
			else {
				phoprimeG(Y, M, input, C, mlen);
				M += mlen;
			}


			xor_topbar_blockG(input, input, offset);
			/* T = E(X[m+a]) */
			giftb128G(input, K, Y);
		}

		memcpy(C, Y, CRYPTO_ABYTES);
	}
}

__global__ void crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec, const uint8_t* npub, const uint8_t* k) {

	*clen = mlen + CRYPTO_ABYTES;

	/* Determine matrix index for each data*/
	uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
	uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
	uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + threadIdx.y;
	uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
	uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
	uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
	uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
	uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
	uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

	//read in col , write in row
	uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
	uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
	uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
	uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
	uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
	uint32_t tai = taiy * adlen + taix; // access in columns - ad 
	uint32_t tao = taix * adlen + taiy; // access in columns - ad 
	uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko, tao, tmo, tci,tn);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + blockDim.x, tao + blockDim.x, tmo + blockDim.x, tci + blockDim.x,tn + blockDim.x);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + 2 * blockDim.x, tao + 2 * blockDim.x, tmo + 2 * blockDim.x, tci + 2 * blockDim.x, tn + 2* blockDim.x);
	encrypt_unroll4(c, clen, m, mlen, ad, adlen, nsec, npub, k, tko + 3 * blockDim.x, tao + 3 * blockDim.x, tmo + 3 * blockDim.x, tci + 3 * blockDim.x, tn + 3* blockDim.x);

}

__global__ void crypto_aead_encrypt_gpu_global_Op_Register_Trans(
	uint8_t* c, uint64_t* clen,
	const uint8_t* m, uint64_t mlen,
	const uint8_t* ad, uint64_t adlen,
	const uint8_t* nsec,
	const uint8_t* npub,
	const uint8_t* k)
{
	(void)nsec;
	*clen = mlen + TAGBYTES;

	if ((blockIdx.x * blockDim.x + threadIdx.x) < BATCH) {
		/* Determine matrix index for each data*/
		uint32_t tkix = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tkiy = blockDim.x * blockIdx.x * CRYPTO_KEYBYTES + threadIdx.y;
		uint32_t tnix = blockDim.x * blockIdx.x * CRYPTO_NPUBBYTES + threadIdx.x;		//For Nonce and key - same because both 16 fixed
		uint32_t tniy = blockDim.x * blockIdx.y * CRYPTO_NPUBBYTES + threadIdx.y;
		uint32_t tmix = blockDim.x * blockIdx.x * mlen + threadIdx.y;					//for message with message len
		uint32_t tmiy = blockDim.x * blockIdx.x * mlen + threadIdx.y;
		uint32_t taix = blockDim.x * blockIdx.x * adlen + threadIdx.x;					//for additional data len
		uint32_t taiy = blockDim.x * blockIdx.x * adlen + threadIdx.y;
		uint32_t tcix = blockDim.x * blockIdx.x * (*clen) + threadIdx.x;				//for cipher text
		uint32_t tciy = blockDim.x * blockIdx.x * (*clen) + threadIdx.y;

		//read in col , write in row
		uint32_t tki = tkiy * CRYPTO_KEYBYTES + tkix; // access in rows - key & nonce
		uint32_t tko = tkix * CRYPTO_KEYBYTES + tkiy; // access in columns - key & nonce
		uint32_t tn = tniy * CRYPTO_NPUBBYTES + tnix; // access in columns - nonce
		uint32_t tmi = tmiy * mlen + tmix; // access in rows - message 
		uint32_t tmo = tmix * mlen + tmiy; // access in columns - message 
		uint32_t tai = taiy * adlen + taix; // access in columns - ad 
		uint32_t tao = taix * adlen + taiy; // access in columns - ad 
		uint32_t tci = tciy * (*clen) + tcix; // access in row  - cipher

		uint8_t* C = c + tci;
		uint8_t* M = const_cast<uint8_t*>(m) + tmo;
		uint8_t* A = const_cast<uint8_t*>(ad) + tao;
		uint8_t* N = const_cast<uint8_t*>(npub) + tn;
		uint8_t* K = const_cast<uint8_t*>(k) + tko;

		u32 tmp0, tmp1, emptyA, emptyM;
		u32 offset[2], input[4], rkey[80];
		u8 Y[16];

		if (!COFB_ENCRYPT) {
			if (mlen < TAGBYTES)
				return;
			mlen -= TAGBYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		precompute_rkeysG_OpBased(rkey, K);
		giftb128G_NewOp(Y, N, rkey);
		offset[0] = ((u32*)Y)[0];
		offset[1] = ((u32*)Y)[1];

		while (adlen > BLOCKBYTES) {
			RHO1G_Op(input, (u32*)Y, (u32*)A, BLOCKBYTES);

			DOUBLE_HALF_BLOCK(offset);
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
			A += BLOCKBYTES;
			adlen -= BLOCKBYTES;
		}

		TRIPLE_HALF_BLOCK(offset);

		if ((adlen % BLOCKBYTES != 0) || (emptyA)) {
			TRIPLE_HALF_BLOCK(offset);
		}
		if (emptyM) {
			TRIPLE_HALF_BLOCK(offset);
			TRIPLE_HALF_BLOCK(offset);
		}

		RHO1G_Op(input, (u32*)Y, (u32*)A, adlen);
		XOR_TOP_BAR_BLOCK(input, offset);
		giftb128G_NewOp(Y, (u8*)input, rkey);

		while (mlen > BLOCKBYTES) {
			DOUBLE_HALF_BLOCK(offset);

			if (COFB_ENCRYPT)
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);
			else
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);

			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
			M += BLOCKBYTES;
			C += BLOCKBYTES;
			mlen -= BLOCKBYTES;
		}

		if (!emptyM) {
			TRIPLE_HALF_BLOCK(offset);

			if (mlen % BLOCKBYTES != 0) {
				TRIPLE_HALF_BLOCK(offset);
			}
			if (COFB_ENCRYPT) {
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, mlen);
				C += mlen;
			}
			else {
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, mlen);
				M += mlen;
			}
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_NewOp(Y, (u8*)input, rkey);
		}

		if (COFB_ENCRYPT) {
			memcpy(C, Y, TAGBYTES);
		}
	}
}

int main()
{
#ifdef WRITEFILE
	FILE* fpt;
	fpt = fopen("Giftcofb_CA_raw.csv", "w");
	fprintf(fpt, "Version, Threads, Latency, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, AEAD/s (full latency), AEAD/s (exclude transpose)\n");
#endif

	uint8_t* nonce, * key, * msg, * ad, * ct, * msg2;
	uint64_t alen = ALEN;	// additional data length
	uint64_t mlen = MLEN;	// messege length
	uint64_t clen;	// cipher length
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
	}

	QueryPerformanceCounter(&t2);
	cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);
#ifdef WRITEFILE
	fprintf(fpt, "%s, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", 0.0, cpu_t, 0.0, 0.0, cpu_t, 0.0, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));
#endif
	printf("Version\t\tConfiguration\tMemcpyH2D\tMemcpyD2H\tLatency\t\tAEAD/s (full latency)\t AEAD/s (exclude transpose)\n\n");
	printf("Host\tSerial\t\t%.6f\t%.6f\t%.6f\t%.f\t%.f\n", 0.0, 0.0, cpu_t, BATCH / (cpu_t / 1000), BATCH / (cpu_t / 1000));


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

	//Parallel Granularity
	for (int i = 64; i < 1025; i *= 2) {

		float memcpy_h2d, elapsed, memcpy_d2h, total;

		for (int z = 1; z < 6; z++) {

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
			else if (z == 3) { // for coleasced
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
			double temp = (double)BATCH / (double)i;
			dim3 blocks(ceil(temp));		
			if (z > 1) {
				threads.y = i;
				temp = (double)BATCH / ((double)threads.x * (double)threads.y);
				blocks.x = ((z == 3) ? ceil(temp / 4) : ceil(temp));
				blocks.x = (blocks.x < 1) ? 1 : blocks.x; 
			}

			kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global : ((z == 2) ? crypto_aead_encrypt_gpu_global_Op_Register  : ((z==3) ? &crypto_aead_encrypt_gpu_rcwr_GpuTranspose : 
				((z==4) ? &crypto_aead_encrypt_gpu_rcwr_GPUTransposeUnroll4 : crypto_aead_encrypt_gpu_global_Op_Register_Trans))));
			char* kernelName = ((z == 1) ? "GPU Unoptimised" : ((z == 2) ? "GPU Reg Op" : ((z==3) ? "GPU Tran" : ((z==4)? "GPU TransU4" : "GPU Reg Trans"))));

			//Kernel execution
			memset(h_c, 0, BATCH * MAX_CIPHER_LENGTH * sizeof(uint8_t));
			cudaEventRecord(start);
			kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k);
			cudaEventRecord(stop);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&elapsed, start, stop);

			//Memory Copy from D2H
			cudaEventRecord(start, 0);
			cudaMemcpy(h_c, d_c, BATCH * (*d_clen) * sizeof(uint8_t), cudaMemcpyDeviceToHost);
			cudaEventRecord(stop, 0);
			cudaEventSynchronize(stop);
			cudaEventElapsedTime(&memcpy_d2h, start, stop);

			checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH);

			double Ttime = 0;
			if (z < 3)
				total = memcpy_h2d + elapsed + memcpy_d2h;
			else {
				total = memcpy_h2d + trans + elapsed + memcpy_d2h;
				Ttime = trans;
			}


			printf("%s\t %u \t\t%.6f\t%.6f\t%.6f  \t%.f \t%.f\n", kernelName, threads.x, memcpy_h2d,
				memcpy_d2h,  total, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#ifdef WRITEFILE
			fprintf(fpt, "%s, %u, %.6f, %.6f, %.6f, %.6f,  %.6f, %.f, %.f\n", kernelName, threads.x, total,
				memcpy_h2d, Ttime, elapsed, memcpy_d2h, BATCH / (total / 1000), BATCH / ((total - Ttime) / 1000));
#endif
		}

		printf("\n======================================================================================================================================================\n");

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

	return 0;
}