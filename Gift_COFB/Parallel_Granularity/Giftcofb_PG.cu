#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <math.h>
#include "operations.h"
#include "params.h"
#include "giftcofb.h"
#include "Giftcofb_Op.h"

int crypto_aead_encrypt_Op(unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec, const unsigned char* npub,
	const unsigned char* k)
{
	(void)nsec;
	*clen = mlen + TAGBYTES;

	u32 tmp0, tmp1, emptyA, emptyM;
	u32 offset[2], input[4], rkey[80];
	u8 Y[16];

	if (!COFB_ENCRYPT) {
		if (mlen < TAGBYTES)
			return -1;
		mlen -= TAGBYTES;
	}

	emptyA = (adlen == 0) ? 1 : 0;
	emptyM = (mlen == 0) ? 1 : 0;

	precompute_rkeys(rkey, k);
	giftb128(Y, npub, rkey);
	offset[0] = ((u32*)Y)[0];
	offset[1] = ((u32*)Y)[1];

	while (adlen > BLOCKBYTES) {
		RHO1(input, (u32*)Y, (u32*)ad, BLOCKBYTES);

		DOUBLE_HALF_BLOCK(offset);
		XOR_TOP_BAR_BLOCK(input, offset);
		giftb128(Y, (u8*)input, rkey);
		ad += BLOCKBYTES;
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

	RHO1(input, (u32*)Y, (u32*)ad, adlen);
	XOR_TOP_BAR_BLOCK(input, offset);
	giftb128(Y, (u8*)input, rkey);

	while (mlen > BLOCKBYTES) {
		DOUBLE_HALF_BLOCK(offset);

		if (COFB_ENCRYPT)
			RHO((u32*)Y, (u32*)m, input, (u32*)c, BLOCKBYTES);
		else
			RHO_PRIME((u32*)Y, (u32*)m, input, (u32*)c, BLOCKBYTES);

		XOR_TOP_BAR_BLOCK(input, offset);
		giftb128(Y, (u8*)input, rkey);
		m += BLOCKBYTES;
		c += BLOCKBYTES;
		mlen -= BLOCKBYTES;
	}

	if (!emptyM) {
		TRIPLE_HALF_BLOCK(offset);

		if (mlen % BLOCKBYTES != 0) {
			TRIPLE_HALF_BLOCK(offset);
		}
		if (COFB_ENCRYPT) {
			RHO((u32*)Y, (u32*)m, input, (u32*)c, mlen);
			c += mlen;
		}
		else {
			RHO_PRIME((u32*)Y, (u32*)m, input, (u32*)c, mlen);
			m += mlen;
		}
		XOR_TOP_BAR_BLOCK(input, offset);
		giftb128(Y, (u8*)input, rkey);
	}

	if (COFB_ENCRYPT) {
		memcpy(c, Y, TAGBYTES);
		return 0;
	}
	//decrypting
	tmp0 = 0;
	for (tmp1 = 0; tmp1 < TAGBYTES; tmp1++)
		tmp0 |= m[tmp1] ^ Y[tmp1];
	return tmp0;
}

//Global no transpose
__global__ void crypto_aead_encrypt_gpu_global(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int BATCH)
{
	*clen = mlen + CRYPTO_ABYTES;

	int tid = threadIdx.x, bid = blockIdx.x;
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
	while (adlen > 16) {
		pho1G(input, Y, A, 16);
		double_half_blockG(offset, offset);
		xor_topbar_blockG(input, input, offset);
		giftb128G(input, K, Y);

		A = A + 16;
		adlen -= 16;
	}
	/* last block */
	triple_half_blockG(offset, offset);
	if ((adlen % 16 != 0) || (emptyA)) {
		triple_half_blockG(offset, offset);
	}

	if (emptyM) {
		triple_half_blockG(offset, offset);
		triple_half_blockG(offset, offset);
	}
	pho1G(input, Y, A, adlen);

	xor_topbar_blockG(input, input, offset);
	giftb128G(input, K, Y);


	/* Process M */
	while (mlen > 16) {
		double_half_blockG(offset, offset);
		if (COFB_ENCRYPT) {
			phoG(Y, M, input, C, 16);
		}
		else {
			phoprimeG(Y, M, input, C, 16);
		}

		xor_topbar_blockG(input, input, offset);
		giftb128G(input, K, Y);

		M = M + 16;
		C = C + 16;
		mlen -= 16;
	}

	if (!emptyM) {
		triple_half_blockG(offset, offset);
		if (mlen % 16 != 0) {
			triple_half_blockG(offset, offset);
		}
		if (COFB_ENCRYPT) {
			phoG(Y, M, input, C, mlen);
			C += mlen;
		}
		else {
			phoprimeG(Y, M, input, C, mlen);
			M += mlen;
		}


		xor_topbar_blockG(input, input, offset);
		giftb128G(input, K, Y);
	}

	memcpy(C, Y, CRYPTO_ABYTES);
}


//Global Optimised Ref
__global__ void crypto_aead_encrypt_gpu_global_OpBased(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int BATCH)
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
		giftb128G_Op(Y, N, rkey);
		offset[0] = ((u32*)Y)[0];
		offset[1] = ((u32*)Y)[1];

		while (adlen > BLOCKBYTES) {
			RHO1G_Op(input, (u32*)Y, (u32*)A, BLOCKBYTES);

			DOUBLE_HALF_BLOCK(offset);
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_Op(Y, (u8*)input, rkey);
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
		giftb128G_Op(Y, (u8*)input, rkey);

		while (mlen > BLOCKBYTES) {
			DOUBLE_HALF_BLOCK(offset);

			if (COFB_ENCRYPT)
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);
			else
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);

			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_Op(Y, (u8*)input, rkey);
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
			giftb128G_Op(Y, (u8*)input, rkey);
		}

		if (COFB_ENCRYPT) {
			memcpy(C, Y, TAGBYTES);
		}
	}
}


//Global - register change version
__global__ void crypto_aead_encrypt_gpu_global_Op_Register(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int BATCH)
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


//Global Optimised - fine thread
__global__ void crypto_aead_encrypt_gpu_global_FineOp(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int BATCH)
{
	(void)nsec;
	*clen = mlen + TAGBYTES;

	int tid = threadIdx.x, bid = blockIdx.x;
	if ((bid * blockDim.x + (tid / fineLevel)) < BATCH) {

		uint32_t offset_msg = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + ((tid / fineLevel) * adlen);			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES); //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (*clen) + ((tid / fineLevel) * (*clen));	//instead of crypto_abytes

		//printf("id - %d\t tid - %d\t offset - %d\n", (bid * blockDim.x + tid), threadIdx.x, offset_msg);

		u8 * M = const_cast<u8*>(m + offset_msg);
		u8 * A = const_cast<u8*>(ad + offset_ad);
		u8 * N = const_cast<u8*>(npub + offset_nonce);
		u8 * K = const_cast<u8*>(k + offset_key);
		u8 * C = const_cast<u8*>(c + offset_ct);

		u32 tmp0, tmp1, emptyA, emptyM;
		u32 offset[2], input[4];
		u8 Y[16];

		if (!COFB_ENCRYPT) {
			if (mlen < TAGBYTES)
				return;
			mlen -= TAGBYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		precompute_rkeysG_FineOp(K);
		giftb128G_FineOp(Y, N);
		offset[0] = ((u32*)Y)[0];
		offset[1] = ((u32*)Y)[1];

		while (adlen > BLOCKBYTES) {
			RHO1G_Op(input, (u32*)Y, (u32*)A, BLOCKBYTES);

			DOUBLE_HALF_BLOCK(offset);
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_FineOp(Y, (u8*)input);
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
		giftb128G_FineOp(Y, (u8*)input);

		while (mlen > BLOCKBYTES) {
			DOUBLE_HALF_BLOCK(offset);

			if (COFB_ENCRYPT)
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);
			else
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);

			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_FineOp(Y, (u8*)input);
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
			giftb128G_FineOp(Y, (u8*)input);
		}

		if (COFB_ENCRYPT && (tid % fineLevel == 0)) {
			memcpy(C, Y, TAGBYTES);
		}
	}
}

//Global Optimised - fine thread + register
__global__ void crypto_aead_encrypt_gpu_global_FineOp_Register(
	uint8_t * c, uint64_t * clen,
	const uint8_t * m, uint64_t mlen,
	const uint8_t * ad, uint64_t adlen,
	const uint8_t * nsec,
	const uint8_t * npub,
	const uint8_t * k,
	int BATCH)
{
	(void)nsec;
	*clen = mlen + TAGBYTES;

	int tid = threadIdx.x, bid = blockIdx.x;
	if ((bid * blockDim.x + (tid / fineLevel)) < BATCH) {

		uint32_t offset_msg = bid * blockDim.x * mlen + ((tid / fineLevel) * mlen);			// message
		uint32_t offset_ad = bid * blockDim.x * adlen + ((tid / fineLevel) * adlen);			// AD
		uint32_t offset_key = bid * blockDim.x * CRYPTO_KEYBYTES + ((tid / fineLevel) * CRYPTO_KEYBYTES); //key and nonce read only 16
		uint32_t offset_nonce = bid * blockDim.x * CRYPTO_NPUBBYTES + ((tid / fineLevel) * CRYPTO_NPUBBYTES); //key and nonce read only 16
		uint32_t offset_ct = bid * blockDim.x * (*clen) + ((tid / fineLevel) * (*clen));	//instead of crypto_abytes

		u8 * M = const_cast<u8*>(m + offset_msg);
		u8 * A = const_cast<u8*>(ad + offset_ad);
		u8 * N = const_cast<u8*>(npub + offset_nonce);
		u8 * K = const_cast<u8*>(k + offset_key);
		u8 * C = const_cast<u8*>(c + offset_ct);

		u32 tmp0, tmp1, emptyA, emptyM;
		u32 offset[2], input[4];
		u8 Y[16];

		if (!COFB_ENCRYPT) {
			if (mlen < TAGBYTES)
				return;
			mlen -= TAGBYTES;
		}

		emptyA = (adlen == 0) ? 1 : 0;
		emptyM = (mlen == 0) ? 1 : 0;

		precompute_rkeysG_FineOp(K);
		giftb128G_FineOp_Register(Y, N);
		offset[0] = ((u32*)Y)[0];
		offset[1] = ((u32*)Y)[1];

		while (adlen > BLOCKBYTES) {
			RHO1G_Op(input, (u32*)Y, (u32*)A, BLOCKBYTES);

			DOUBLE_HALF_BLOCK(offset);
			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_FineOp_Register(Y, (u8*)input);
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
		giftb128G_FineOp_Register(Y, (u8*)input);

		while (mlen > BLOCKBYTES) {
			DOUBLE_HALF_BLOCK(offset);

			if (COFB_ENCRYPT)
				RHOG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);
			else
				RHO_PRIMEG_Op((u32*)Y, (u32*)M, input, (u32*)C, BLOCKBYTES);

			XOR_TOP_BAR_BLOCK(input, offset);
			giftb128G_FineOp_Register(Y, (u8*)input);
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
			giftb128G_FineOp_Register(Y, (u8*)input);
		}

		if (COFB_ENCRYPT && (tid % fineLevel == 0)) {
			memcpy(C, Y, TAGBYTES);
		}
	}
}

int main()
{

#ifdef WRITEFILE
	FILE* fpt;
	char writeFile[100];
	char fineLvl[1];
	strcpy(writeFile, "Giftcofb_PG_F");
	sprintf(fineLvl, "%d", fineLevel);
	strcat(writeFile, fineLvl);
	strcat(writeFile, ".csv");
	fpt = fopen(writeFile, "w");
	fprintf(fpt, "Version, Size, Dimension, Throughput, Latency, Speed Up (Latency), Gbps, Memcpy H2D, Transpose, Execution Time, Memcpy D2H, Speed UP (Execution), AEAD/s, Throughput(Times)\n");
#endif

	int BATCH[BATCH_SIZE] = { 64000,256000,1000000,4000000,16000000 };

	for (int a = 0; a < BATCH_SIZE; a++) {
		printf("\nSize Implementation : %d\n", BATCH[a]);

		uint8_t* nonce, * key, * msg, * ad, * ct;
		uint64_t alen = ALEN;	// additional data length
		uint64_t mlen = MLEN;	// messege length
		uint64_t clen = MAX_CIPHER_LENGTH;		// cipher length
		LARGE_INTEGER frequency;
		LARGE_INTEGER t1, t2;
		double cpu_t = 0;

		cudaMallocHost((void**)& key, BATCH[a] * CRYPTO_KEYBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& nonce, BATCH[a] * CRYPTO_NPUBBYTES * sizeof(uint8_t));
		cudaMallocHost((void**)& msg, BATCH[a] * mlen * sizeof(uint8_t));
		cudaMallocHost((void**)& ad, BATCH[a] * alen * sizeof(uint8_t));
		cudaMallocHost((void**)& ct, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t));

		init_buffer('k', key, CRYPTO_KEYBYTES, BATCH[a]);
		init_buffer('n', nonce, CRYPTO_NPUBBYTES, BATCH[a]);
		init_buffer('m', msg, mlen, BATCH[a]);
		init_buffer('a', ad, alen, BATCH[a]);


		cpu_t = 0;
		QueryPerformanceFrequency(&frequency);
		QueryPerformanceCounter(&t1);
		for (int i = 0; i < BATCH[a]; i++) {

			int result = crypto_aead_encrypt_Op(OFFSET(ct, i, clen), &clen, OFFSET(msg, i, mlen), mlen, OFFSET(ad, i, alen),
				alen, NULL, OFFSET(nonce, i, CRYPTO_NPUBBYTES), OFFSET(key, i, CRYPTO_KEYBYTES));

		}
		QueryPerformanceCounter(&t2);
		cpu_t = 0;
		cpu_t += ((double)(t2.QuadPart - t1.QuadPart) * 1000.0 / (double)frequency.QuadPart);

#ifdef WRITEFILE
		fprintf(fpt, "%s, %d,%d, %.6f, %.6f, %.6f, %.6f,%.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f\n", "Host", BATCH[a], 0, ((BATCH[a] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t, cpu_t, 0.0, (((BATCH[a] * clen * sizeof(uint8_t)) * 1e-6) / cpu_t) * 8, 0.0, 0.0, cpu_t, 0.0, 0.0, BATCH[a] / (cpu_t / 1000), 0.0);
#endif
		printf("Version\t\t        Latency\t\tAEAD/s\n\n");
		printf("Host\t\t\t%.6f \t\t%.f\n", cpu_t, BATCH[a] / (cpu_t / 1000));

		//GPU implementation
		uint8_t * d_n, *d_k, *d_a, *d_m, *d_c, *h_c;
		uint64_t * d_clen;
		cudaEvent_t start, stop;

		cudaEventCreate(&start);
		cudaEventCreate(&stop);

		//Memory Allocation - Device
		cudaMallocHost((void**)& h_c, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t));		//Host Cipher
		cudaMalloc((void**)& d_c, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t));			//Device Cipher
		cudaMalloc((void**)& d_n, BATCH[a] * CRYPTO_NPUBBYTES * sizeof(uint8_t));			//Nonce
		cudaMalloc((void**)& d_k, BATCH[a] * CRYPTO_KEYBYTES * sizeof(uint8_t));				//Key
		cudaMalloc((void**)& d_m, BATCH[a] * (uint64_t)mlen * sizeof(uint8_t));				//Message
		cudaMalloc((void**)& d_a, BATCH[a] * (uint64_t)alen * sizeof(uint8_t));				//Additional Data
		cudaMallocHost((void**)& d_clen, sizeof(uint64_t));
		*d_clen = MAX_CIPHER_LENGTH;

		//Memory Copy from H2D
		cudaEventRecord(start, 0);
		cudaMemcpy(d_n, nonce, BATCH[a] * CRYPTO_NPUBBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_k, key, BATCH[a] * CRYPTO_KEYBYTES * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_m, msg, BATCH[a] * (uint64_t)mlen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaMemcpy(d_a, ad, BATCH[a] * (uint64_t)alen * sizeof(uint8_t), cudaMemcpyHostToDevice);
		cudaEventRecord(stop, 0);
		cudaEventSynchronize(stop);
		float memcpy_h2d;
		cudaEventElapsedTime(&memcpy_h2d, start, stop);
		void (*kernel)(uint8_t*, uint64_t*, const uint8_t*, uint64_t, const uint8_t*, uint64_t, const uint8_t*, const uint8_t*, const uint8_t*, int);
		size_t size = BATCH[a] * (*d_clen) * sizeof(uint8_t);

		//Parallel Granularity
		for (int i = 1; i < Tlimit; i *= 2) {

			float elapsed, memcpy_d2h, total;

			for (int z = 1; z < 4; z++) {
				dim3 threads(i);
				double temp = (double)BATCH[a] / (double)i;
				dim3 blocks(ceil(temp));

				kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global : ((z == 2) ? &crypto_aead_encrypt_gpu_global_OpBased : &crypto_aead_encrypt_gpu_global_Op_Register));
				char* kernelName = ((z == 1) ? "GPU Ref  " : ((z == 2) ? "GPU OpRef" : "GPU Reg   "));

				//Kernel execution
				memset(h_c, 0, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
				cudaEventRecord(start, 0);
				kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[a]);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				elapsed = 0;
				cudaEventElapsedTime(&elapsed, start, stop);

				//Memory Copy from D2H
				cudaEventRecord(start, 0);
				cudaMemcpy(h_c, d_c, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
				cudaEventRecord(stop, 0);
				cudaEventSynchronize(stop);
				memcpy_d2h = 0;
				cudaEventElapsedTime(&memcpy_d2h, start, stop);
				checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH, z, BATCH[a]);
#ifdef WRITEFILE
				PrintTime(ct, h_c, &clen, i, memcpy_d2h, elapsed, memcpy_d2h, cpu_t, fpt, BATCH[a], kernelName);
#else
				PrintTime(ct, h_c, &clen, i, memcpy_d2h, elapsed, memcpy_d2h, cpu_t, NULL, BATCH[a], kernelName);
#endif

			}

			//For fine grain
			if (i == fineLevel) {

				for (int z = 1; z < 3; z++) {
					dim3 threads(Tlimit); //fine grain each block max 512 threads to divide by 4/8/16 threads for fine grain.
					double temp = ((double)BATCH[a] / (Tlimit / (double)fineLevel));
					dim3 blocks(ceil(temp));		

					kernel = ((z == 1) ? &crypto_aead_encrypt_gpu_global_FineOp : crypto_aead_encrypt_gpu_global_FineOp_Register);
					char* kernelName = ((z == 1) ? "GPU Fine 4" : "GPU FineReg 4"); //alter here

					//Kernel execution
					memset(h_c, 0, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t));
					cudaEventRecord(start, 0);
					kernel << <blocks, threads >> > (d_c, d_clen, d_m, mlen, d_a, alen, NULL, d_n, d_k, BATCH[a]);
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					elapsed = 0;
					cudaEventElapsedTime(&elapsed, start, stop);

					//Memory Copy from D2H
					cudaEventRecord(start, 0);
					cudaMemcpy(h_c, d_c, BATCH[a] * MAX_CIPHER_LENGTH * sizeof(uint8_t), cudaMemcpyDeviceToHost);
					cudaEventRecord(stop, 0);
					cudaEventSynchronize(stop);
					memcpy_d2h = 0;
					cudaEventElapsedTime(&memcpy_d2h, start, stop);

					checkResult(kernelName, ct, h_c, MAX_CIPHER_LENGTH, z, BATCH[a]);

					total = memcpy_h2d + elapsed + memcpy_d2h;

					printf("KernelT%d :\t%.6f ms\t\t%.f \t%s\n", fineLevel, total, BATCH[a] / (total / 1000), kernelName);
#ifdef WRITEFILE
					fprintf(fpt, "T%d,%d,%.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f, %.f, %.2f,%s\n", fineLevel, BATCH, (size * 2e-6) / total, total, (cpu_t / total), ((size * 2e-6) / total) * 8, memcpy_d2h, elapsed, (cpu_t / elapsed), BATCH[a] / (total / 1000), (BATCH[a] / (total / 1000)) / (BATCH[a] / (cpu_t / 1000)), kernelName);
#endif
				}

			}

		}
		printf("\n======================================================================================================================================================\n");

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
	}
#ifdef WRITEFILE
	fclose(fpt);
#endif
	cudaDeviceReset();

	return 0;
}
