#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "params.h"

/*XOODOO*/
__device__ static uint32_t rotlG(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
	c &= mask;
	return (n << c) | (n >> ((-c) & mask));
}

__device__ void Xoodoo_InitializeG(void* state)
{
	memset(state, 0, NLANES * sizeof(tXoodooLane));
}

__device__ void Xoodoo_AddByteG(void* state, unsigned char byte, unsigned int offset)
{
	///assert(offset < NLANES * sizeof(tXoodooLane));
	((unsigned char*)state)[offset] ^= byte;
}
//
//__device__ void Xoodoo_OverwriteBytesG(void* state, const unsigned char* data, unsigned int offset, unsigned int length)
//{
//	//assert(offset < NLANES * sizeof(tXoodooLane));
//	//assert(offset + length <= NLANES * sizeof(tXoodooLane));
//	memcpy((unsigned char*)state + offset, data, length);
//}

//__device__ void Xoodoo_OverwriteWithZeroesG(void* state, unsigned int byteCount)
//{
//	assert(byteCount <= NLANES * sizeof(tXoodooLane));
//	memset(state, 0, byteCount);
//}

//__device__ void Xoodoo_ExtractBytesG(const void* state, unsigned char* data, unsigned int offset, unsigned int length)
//{
//	assert(offset < NLANES * sizeof(tXoodooLane));
//	assert(offset + length <= NLANES * sizeof(tXoodooLane));
//	memcpy(data, (unsigned char*)state + offset, length);
//}

__device__ void Xoodoo_ExtractAndAddBytesG(const void* state, const unsigned char* input, unsigned char* output, unsigned int offset, unsigned int length)
{
	unsigned int i;
	/*assert(offset < NLANES * sizeof(tXoodooLane));
	assert(offset + length <= NLANES * sizeof(tXoodooLane));*/
	for (i = 0; i < length; i++)
		output[i] = input[i] ^ ((unsigned char*)state)[offset + i];
}


__device__ static void fromBytesToWordsG(tXoodooLane* stateAsWords, const unsigned char* state)
{
	unsigned int i, j;

	for (i = 0; i < NLANES; i++) {
		stateAsWords[i] = 0;
		for (j = 0; j < sizeof(tXoodooLane); j++)
			stateAsWords[i] |= (tXoodooLane)(state[i * sizeof(tXoodooLane) + j]) << (8 * j);
	}
}

__device__ static void fromWordsToBytesG(unsigned char* state, const tXoodooLane* stateAsWords)
{
	unsigned int i, j;

	for (i = 0; i < NLANES; i++)
		for (j = 0; j < sizeof(tXoodooLane); j++)
			state[i * sizeof(tXoodooLane) + j] = (stateAsWords[i] >> (8 * j)) & 0xFF;
}


__device__ static void Xoodoo_RoundG(tXoodooLane* a, tXoodooLane rc)
{
	unsigned int x, y;
	tXoodooLane    b[NLANES];
	tXoodooLane    p[NCOLUMS];
	tXoodooLane    e[NCOLUMS];

	/* Theta: Column Parity Mixer */
	for (x = 0; x < NCOLUMS; ++x)
		p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
	for (x = 0; x < NCOLUMS; ++x)
		e[x] = rotlG(p[(x - 1) % 4], 5) ^ rotlG(p[(x - 1) % 4], 14);
	for (x = 0; x < NCOLUMS; ++x)
		for (y = 0; y < NROWS; ++y)
			a[index(x, y)] ^= e[x];
	//Dump("Theta", a, 2);

	/* Rho-west: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = a[index(x - 1, 1)];
		b[index(x, 2)] = rotlG(a[index(x, 2)], 11);
	}

	memcpy(a, b, sizeof(b));

	/* Iota: round constant */
	a[0] ^= rc;

	/* Chi: non linear layer */
	for (x = 0; x < NCOLUMS; ++x)
		for (y = 0; y < NROWS; ++y)
			b[index(x, y)] = a[index(x, y)] ^ (~a[index(x, y + 1)] & a[index(x, y + 2)]);
	memcpy(a, b, sizeof(b));

	/* Rho-east: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = rotlG(a[index(x, 1)], 1);
		b[index(x, 2)] = rotlG(a[index(x + 2, 2)], 8);
	}
	memcpy(a, b, sizeof(b));

}

__device__ static const uint32_t    RCG[MAXROUNDS] = {
	_rc12,
	_rc11,
	_rc10,
	_rc9,
	_rc8,
	_rc7,
	_rc6,
	_rc5,
	_rc4,
	_rc3,
	_rc2,
	_rc1
};

__device__ static  void Xoodoo_Permute_NroundsG(void* state, uint32_t nr)
{
	tXoodooLane        a[NLANES];
	unsigned int    i;

	fromBytesToWordsG(a, (const unsigned char*)state);

	for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {
		Xoodoo_RoundG(a, RCG[i]);
	}
	fromWordsToBytesG((unsigned char*)state, a);

}

/*XOODYAK*/

// Initialise
__device__ static void Xoodyak_DownG(Xoodyak_Instance* instance, const uint8_t* Xi, unsigned int XiLen, uint8_t Cd)
{
	unsigned int i;
	for (i = 0; i < XiLen; i++)
		((unsigned char*)instance->state)[0 + i] ^= Xi[i];

	((unsigned char*)instance->state)[XiLen] ^= 0x01;
	((unsigned char*)instance->state)[Xoodoo_stateSizeInBytes - 1] ^= (instance->mode == Cyclist_ModeHash) ? (Cd & 0x01) : Cd;

	//Xoodoo_AddByteG(instance->state, (instance->mode == Cyclist_ModeHash) ? (Cd & 0x01) : Cd, Xoodoo_stateSizeInBytes - 1);
	instance->phase = Cyclist_PhaseDown;

}

__device__ static void Xoodyak_UpG(Xoodyak_Instance* instance, uint8_t* Yi, unsigned int YiLen, uint8_t Cu)
{
	if (instance->mode != Cyclist_ModeHash) {
		((unsigned char*)instance->state)[Xoodoo_stateSizeInBytes - 1] ^= Cu;
	}
	Xoodoo_Permute_NroundsG(&(instance->state), PERMUTATION_ROUND);
	instance->phase = Cyclist_PhaseUp;

	if (Yi != NULL) {
		memcpy(Yi, (unsigned char*)instance->state + 0, YiLen);
	}
}

__device__ static void Xoodyak_AbsorbAnyG(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen, unsigned int r, uint8_t Cd)
{
	unsigned int splitLen;

	do {
		if (instance->phase != Cyclist_PhaseUp) {
			Xoodyak_UpG(instance, NULL, 0, 0);
		}
		splitLen = MyMin(XLen, r);
		Xoodyak_DownG(instance, X, splitLen, Cd);
		Cd = 0;
		X += splitLen;
		XLen -= splitLen;
	} while (XLen != 0);
}


__device__ static void Xoodyak_AbsorbKeyG(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	uint8_t KID[Cyclist_Rkin];

	instance->mode = Cyclist_ModeKeyed;
	instance->Rabsorb = Cyclist_Rkin;
	//instance->Rsqueeze = Cyclist_Rkout;
	if (KLen != 0) {
		memcpy(KID, K, KLen);
		memcpy(KID + KLen, ID, IDLen);
		KID[KLen + IDLen] = (uint8_t)IDLen;
		Xoodyak_AbsorbAnyG(instance, KID, KLen + IDLen + 1, instance->Rabsorb, 0x02);
		if (counterLen != 0) {
			Xoodyak_AbsorbAnyG(instance, counter, counterLen, 1, 0x00);
		}
	}
}

__device__ void Xoodyak_InitializeG(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	Xoodoo_InitializeG(instance->state);
	instance->phase = Cyclist_PhaseUp;
	instance->mode = Cyclist_ModeHash;
	instance->Rabsorb = Cyclist_Rhash;
	instance->Rsqueeze = Cyclist_Rhash;

	if (KLen != 0) {
		Xoodyak_AbsorbKeyG(instance, K, KLen, ID, IDLen, counter, counterLen);
	}
}

// Absorb

__device__ void Xoodyak_AbsorbG(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen)
{
	Xoodyak_AbsorbAnyG(instance, X, XLen, instance->Rabsorb, 0x03);
}

// Encrypt

__device__ static void Xoodyak_CryptG(Xoodyak_Instance* instance, const uint8_t* I, uint8_t* O, size_t IOLen, int decrypt)
{
	unsigned int splitLen;
	uint8_t      P[Cyclist_Rkout];
	uint8_t      Cu = 0x80;

	do {
		splitLen = MyMin(IOLen, Cyclist_Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
		if (decrypt != 0) {
			Xoodyak_UpG(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytesG(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_DownG(instance, O, splitLen, 0x00);
		}
		else {
			memcpy(P, I, splitLen);
			Xoodyak_UpG(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytesG(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_DownG(instance, P, splitLen, 0x00);
		}
		Cu = 0x00;
		I += splitLen;
		O += splitLen;
		IOLen -= splitLen;
	} while (IOLen != 0);
}

__device__ void Xoodyak_EncryptG(Xoodyak_Instance* instance, const uint8_t* P, uint8_t* C, size_t PLen)
{
	Xoodyak_CryptG(instance, P, C, PLen, 0);
}

__device__ void Xoodyak_DecryptG(Xoodyak_Instance* instance, const uint8_t* C, uint8_t* P, size_t CLen)
{
	Xoodyak_CryptG(instance, C, P, CLen, 1);
}

// Squeeze 
__device__ static void Xoodyak_SqueezeAnyG(Xoodyak_Instance* instance, uint8_t* Y, size_t YLen, uint8_t Cu)
{
	unsigned int len;

	len = MyMin(YLen, instance->Rsqueeze);
	Xoodyak_UpG(instance, Y, len, Cu);
	Y += len;
	YLen -= len;
	while (YLen != 0) {
		Xoodyak_DownG(instance, NULL, 0, 0);
		len = MyMin(YLen, instance->Rsqueeze);
		Xoodyak_UpG(instance, Y, len, 0);
		Y += len;
		YLen -= len;
	}
}

//////////////////////////////////////////////////////////////
////////////////      GPU OPtimised                ///////////

__device__ static void Xoodoo_RoundG_Op(tXoodooLane* a, tXoodooLane rc)
{
	unsigned int x, y;
	__shared__ tXoodooLane    b[NLANES];
	__shared__ tXoodooLane    p[NCOLUMS];
	__shared__ tXoodooLane    e[NCOLUMS];

	/* Theta: Column Parity Mixer */
	for (x = 0; x < NCOLUMS; ++x)
		p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
	for (x = 0; x < NCOLUMS; ++x)
		e[x] = rotlG(p[(x - 1) % 4], 5) ^ rotlG(p[(x - 1) % 4], 14);
	for (x = 0; x < NCOLUMS; ++x)
		for (y = 0; y < NROWS; ++y)
			a[index(x, y)] ^= e[x];
	//Dump("Theta", a, 2);

	/* Rho-west: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = a[index(x - 1, 1)];
		b[index(x, 2)] = rotlG(a[index(x, 2)], 11);
	}

	memcpy(a, b, sizeof(b));

	/* Iota: round constant */
	a[0] ^= rc;

	/* Chi: non linear layer */
	for (x = 0; x < NCOLUMS; ++x) {
		//for (y = 0; y < NROWS; ++y)
		b[index(x, y)] = a[index(x, y)] ^ (~a[index(x, y + 1)] & a[index(x, y + 2)]);
		b[index(x, y + 1)] = a[index(x, y + 1)] ^ (~a[index(x, y + 1 + 1)] & a[index(x, y + 2 + 1)]);
		b[index(x, y + 2)] = a[index(x, y + 2)] ^ (~a[index(x, y + 1 + 2)] & a[index(x, y + 2 + 2)]);
	}

	memcpy(a, b, sizeof(b));

	/* Rho-east: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = rotlG(a[index(x, 1)], 1);
		b[index(x, 2)] = rotlG(a[index(x + 2, 2)], 8);
	}
	memcpy(a, b, sizeof(b));

}

__device__ static  void Xoodoo_Permute_NroundsG_Op(void* state, uint32_t nr)
{
	tXoodooLane        a[NLANES];
	unsigned int    i;

	fromBytesToWordsG(a, (const unsigned char*)state);

	for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {
		Xoodoo_RoundG_Op(a, RCG[i]);
	}
	fromWordsToBytesG((unsigned char*)state, a);

}

__device__ static void Xoodyak_UpG_Op(Xoodyak_Instance* instance, uint8_t* Yi, unsigned int YiLen, uint8_t Cu)
{
	if (instance->mode != Cyclist_ModeHash) {
		((unsigned char*)instance->state)[Xoodoo_stateSizeInBytes - 1] ^= Cu;
	}
	Xoodoo_Permute_NroundsG_Op(&(instance->state), PERMUTATION_ROUND);
	instance->phase = Cyclist_PhaseUp;

	if (Yi != NULL) {
		memcpy(Yi, (unsigned char*)instance->state + 0, YiLen);
	}
}


__device__ static void Xoodyak_AbsorbAnyG_Op(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen, unsigned int r, uint8_t Cd)
{
	unsigned int splitLen;

	do {
		if (instance->phase != Cyclist_PhaseUp) {
			Xoodyak_UpG_Op(instance, NULL, 0, 0);
		}
		splitLen = MyMin(XLen, r);
		Xoodyak_DownG(instance, X, splitLen, Cd);
		Cd = 0;
		X += splitLen;
		XLen -= splitLen;
	} while (XLen != 0);
}


__device__ static void Xoodyak_AbsorbKeyG_Op(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	uint8_t KID[Cyclist_Rkin];

	instance->mode = Cyclist_ModeKeyed;
	instance->Rabsorb = Cyclist_Rkin;
	//instance->Rsqueeze = Cyclist_Rkout;
	if (KLen != 0) {
		memcpy(KID, K, KLen);
		memcpy(KID + KLen, ID, IDLen);
		KID[KLen + IDLen] = (uint8_t)IDLen;
		Xoodyak_AbsorbAnyG_Op(instance, KID, KLen + IDLen + 1, instance->Rabsorb, 0x02);
		if (counterLen != 0) {
			Xoodyak_AbsorbAnyG_Op(instance, counter, counterLen, 1, 0x00);
		}
	}
}

__device__ void Xoodyak_InitializeG_Op(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	Xoodoo_InitializeG(instance->state);
	instance->phase = Cyclist_PhaseUp;
	instance->mode = Cyclist_ModeHash;
	instance->Rabsorb = Cyclist_Rhash;
	instance->Rsqueeze = Cyclist_Rhash;

	if (KLen != 0) {
		Xoodyak_AbsorbKeyG_Op(instance, K, KLen, ID, IDLen, counter, counterLen);
	}
}


__device__ static void Xoodyak_CryptG_Op(Xoodyak_Instance* instance, const uint8_t* I, uint8_t* O, size_t IOLen, int decrypt)
{
	unsigned int splitLen;
	uint8_t      P[Cyclist_Rkout];
	uint8_t      Cu = 0x80;

	do {
		splitLen = MyMin(IOLen, Cyclist_Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
		if (decrypt != 0) {
			Xoodyak_UpG_Op(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytesG(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_DownG(instance, O, splitLen, 0x00);
		}
		else {
			memcpy(P, I, splitLen);
			Xoodyak_UpG_Op(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytesG(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_DownG(instance, P, splitLen, 0x00);
		}
		Cu = 0x00;
		I += splitLen;
		O += splitLen;
		IOLen -= splitLen;
	} while (IOLen != 0);
}

__device__ void Xoodyak_EncryptG_Op(Xoodyak_Instance* instance, const uint8_t* P, uint8_t* C, size_t PLen)
{
	Xoodyak_CryptG_Op(instance, P, C, PLen, 0);
}

__device__ void Xoodyak_AbsorbG_Op(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen)
{
	Xoodyak_AbsorbAnyG_Op(instance, X, XLen, instance->Rabsorb, 0x03);
}


__device__ static void Xoodyak_SqueezeAnyG_Op(Xoodyak_Instance* instance, uint8_t* Y, size_t YLen, uint8_t Cu)
{
	unsigned int len;

	len = MyMin(YLen, instance->Rsqueeze);
	Xoodyak_UpG_Op(instance, Y, len, Cu);
	Y += len;
	YLen -= len;
	while (YLen != 0) {
		Xoodyak_DownG(instance, NULL, 0, 0);
		len = MyMin(YLen, instance->Rsqueeze);
		Xoodyak_UpG_Op(instance, Y, len, 0);
		Y += len;
		YLen -= len;
	}
}