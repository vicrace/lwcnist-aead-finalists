#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "params.h"

/*XOODOO*/

void Xoodoo_StaticInitialize(void)
{
}

void Xoodoo_Initialize(void* state)
{
	memset(state, 0, NLANES * sizeof(tXoodooLane));
}

void Xoodoo_AddByte(void* state, unsigned char byte, unsigned int offset)
{
	assert(offset < NLANES * sizeof(tXoodooLane));
	((unsigned char*)state)[offset] ^= byte;
}

void Xoodoo_AddBytes(void* state, const unsigned char* data, unsigned int offset, unsigned int length)
{
	unsigned int i;

	assert(offset < NLANES * sizeof(tXoodooLane));
	assert(offset + length <= NLANES * sizeof(tXoodooLane));
	for (i = 0; i < length; i++)
		((unsigned char*)state)[offset + i] ^= data[i];
}

void Xoodoo_OverwriteBytes(void* state, const unsigned char* data, unsigned int offset, unsigned int length)
{
	assert(offset < NLANES * sizeof(tXoodooLane));
	assert(offset + length <= NLANES * sizeof(tXoodooLane));
	memcpy((unsigned char*)state + offset, data, length);
}

void Xoodoo_OverwriteWithZeroes(void* state, unsigned int byteCount)
{
	assert(byteCount <= NLANES * sizeof(tXoodooLane));
	memset(state, 0, byteCount);
}

void Xoodoo_ExtractBytes(const void* state, unsigned char* data, unsigned int offset, unsigned int length)
{
	assert(offset < NLANES * sizeof(tXoodooLane));
	assert(offset + length <= NLANES * sizeof(tXoodooLane));
	memcpy(data, (unsigned char*)state + offset, length);
}

void Xoodoo_ExtractAndAddBytes(const void* state, const unsigned char* input, unsigned char* output, unsigned int offset, unsigned int length)
{
	unsigned int i;

	assert(offset < NLANES * sizeof(tXoodooLane));
	assert(offset + length <= NLANES * sizeof(tXoodooLane));
	for (i = 0; i < length; i++)
		output[i] = input[i] ^ ((unsigned char*)state)[offset + i];
}


static void fromBytesToWords(tXoodooLane* stateAsWords, const unsigned char* state)
{
	unsigned int i, j;

	for (i = 0; i < NLANES; i++) {
		stateAsWords[i] = 0;
		for (j = 0; j < sizeof(tXoodooLane); j++)
			stateAsWords[i] |= (tXoodooLane)(state[i * sizeof(tXoodooLane) + j]) << (8 * j);
	}
}

static void fromWordsToBytes(unsigned char* state, const tXoodooLane* stateAsWords)
{
	unsigned int i, j;

	for (i = 0; i < NLANES; i++)
		for (j = 0; j < sizeof(tXoodooLane); j++)
			state[i * sizeof(tXoodooLane) + j] = (stateAsWords[i] >> (8 * j)) & 0xFF;
}

static void Xoodoo_Round(tXoodooLane* a, tXoodooLane rc)
{
	unsigned int x, y;
	tXoodooLane    b[NLANES];
	tXoodooLane    p[NCOLUMS];
	tXoodooLane    e[NCOLUMS];

	/* Theta: Column Parity Mixer */
	for (x = 0; x < NCOLUMS; ++x)
		p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
	for (x = 0; x < NCOLUMS; ++x)
		e[x] = ROTL32(p[(x - 1) % 4], 5) ^ ROTL32(p[(x - 1) % 4], 14);
	for (x = 0; x < NCOLUMS; ++x)
		for (y = 0; y < NROWS; ++y)
			a[index(x, y)] ^= e[x];
	Dump("Theta", a, 2);

	/* Rho-west: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = a[index(x - 1, 1)];
		b[index(x, 2)] = ROTL32(a[index(x, 2)], 11);
	}
	memcpy(a, b, sizeof(b));
	Dump("Rho-west", a, 2);

	/* Iota: round constant */
	a[0] ^= rc;
	Dump("Iota", a, 2);

	/* Chi: non linear layer */
	for (x = 0; x < NCOLUMS; ++x)
		for (y = 0; y < NROWS; ++y)
			b[index(x, y)] = a[index(x, y)] ^ (~a[index(x, y + 1)] & a[index(x, y + 2)]);
	memcpy(a, b, sizeof(b));
	Dump("Chi", a, 2);

	/* Rho-east: plane shift */
	for (x = 0; x < NCOLUMS; ++x) {
		b[index(x, 0)] = a[index(x, 0)];
		b[index(x, 1)] = ROTL32(a[index(x, 1)], 1);
		b[index(x, 2)] = ROTL32(a[index(x + 2, 2)], 8);
	}
	memcpy(a, b, sizeof(b));
	Dump("Rho-east", a, 2);

}

static const uint32_t    RC[MAXROUNDS] = {
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

static  void Xoodoo_Permute_Nrounds(void* state, uint32_t nr)
{
	tXoodooLane        a[NLANES];
	unsigned int    i;

	fromBytesToWords(a, (const unsigned char*)state);

	for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {
		Xoodoo_Round(a, RC[i]);
		Dump("Round", a, 1);
	}
	Dump("Permutation", a, 0);
	fromWordsToBytes((unsigned char*)state, a);

}

/*XOODYAK*/

// Initialise
static void Xoodyak_Down(Xoodyak_Instance* instance, const uint8_t* Xi, unsigned int XiLen, uint8_t Cd)
{
	Xoodoo_AddBytes(instance->state, Xi, 0, XiLen);
	Xoodoo_AddByte(instance->state, 0x01, XiLen);
	Xoodoo_AddByte(instance->state, (instance->mode == Cyclist_ModeHash) ? (Cd & 0x01) : Cd, Xoodoo_stateSizeInBytes - 1);
	instance->phase = Cyclist_PhaseDown;

}

static void Xoodyak_Up(Xoodyak_Instance* instance, uint8_t* Yi, unsigned int YiLen, uint8_t Cu)
{
	if (instance->mode != Cyclist_ModeHash) {
		Xoodoo_AddByte(instance->state, Cu, Xoodoo_stateSizeInBytes - 1);
	}
	Xoodoo_Permute_Nrounds(&(instance->state), 12);
	instance->phase = Cyclist_PhaseUp;
	Xoodoo_ExtractBytes(instance->state, Yi, 0, YiLen);
}

static void Xoodyak_AbsorbAny(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen, unsigned int r, uint8_t Cd)
{
	unsigned int splitLen;

	do {
		if (instance->phase != Cyclist_PhaseUp) {
			Xoodyak_Up(instance, NULL, 0, 0);
		}
		splitLen = MyMin(XLen, r);
		Xoodyak_Down(instance, X, splitLen, Cd);
		Cd = 0;
		X += splitLen;
		XLen -= splitLen;
	} while (XLen != 0);
}


static void Xoodyak_AbsorbKey(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	uint8_t KID[Cyclist_Rkin];

	assert(instance->mode == Cyclist_ModeHash);
	assert((KLen + IDLen) <= (Cyclist_Rkin - 1));

	instance->mode = Cyclist_ModeKeyed;
	instance->Rabsorb = Cyclist_Rkin;
	instance->Rsqueeze = Cyclist_Rkout;
	if (KLen != 0) {
		memcpy(KID, K, KLen);
		memcpy(KID + KLen, ID, IDLen);
		KID[KLen + IDLen] = (uint8_t)IDLen;
		Xoodyak_AbsorbAny(instance, KID, KLen + IDLen + 1, instance->Rabsorb, 0x02);
		if (counterLen != 0) {
			Xoodyak_AbsorbAny(instance, counter, counterLen, 1, 0x00);
		}
	}
}

void Xoodyak_Initialize(Xoodyak_Instance* instance, const uint8_t* K, size_t KLen, const uint8_t* ID, size_t IDLen, const uint8_t* counter, size_t counterLen)
{
	Xoodoo_StaticInitialize();
	Xoodoo_Initialize(instance->state);
	instance->phase = Cyclist_PhaseUp;
	instance->mode = Cyclist_ModeHash;
	instance->Rabsorb = Cyclist_Rhash;
	instance->Rsqueeze = Cyclist_Rhash;

	if (KLen != 0) {
		Xoodyak_AbsorbKey(instance, K, KLen, ID, IDLen, counter, counterLen);
	}
}

// Absorb

void Xoodyak_Absorb(Xoodyak_Instance* instance, const uint8_t* X, size_t XLen)
{
	Xoodyak_AbsorbAny(instance, X, XLen, instance->Rabsorb, 0x03);
}

// Encrypt

static void Xoodyak_Crypt(Xoodyak_Instance* instance, const uint8_t* I, uint8_t* O, size_t IOLen, int decrypt)
{
	unsigned int splitLen;
	uint8_t      P[Cyclist_Rkout];
	uint8_t      Cu = 0x80;

	do {
		splitLen = MyMin(IOLen, Cyclist_Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
		if (decrypt != 0) {
			Xoodyak_Up(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytes(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_Down(instance, O, splitLen, 0x00);
		}
		else {
			memcpy(P, I, splitLen);
			Xoodyak_Up(instance, NULL, 0, Cu); /* Up without extract */
			Xoodoo_ExtractAndAddBytes(instance->state, I, O, 0, splitLen); /* Extract from Up and Add */
			Xoodyak_Down(instance, P, splitLen, 0x00);
		}
		Cu = 0x00;
		I += splitLen;
		O += splitLen;
		IOLen -= splitLen;
	} while (IOLen != 0);
}

void Xoodyak_Encrypt(Xoodyak_Instance* instance, const uint8_t* P, uint8_t* C, size_t PLen)
{
	assert(instance->mode == Cyclist_ModeKeyed);
	Xoodyak_Crypt(instance, P, C, PLen, 0);
}

void Xoodyak_Decrypt(Xoodyak_Instance* instance, const uint8_t* C, uint8_t* P, size_t CLen)
{
	assert(instance->mode == Cyclist_ModeKeyed);
	Xoodyak_Crypt(instance, C, P, CLen, 1);
}

// Squeeze 
static void Xoodyak_SqueezeAny(Xoodyak_Instance* instance, uint8_t* Y, size_t YLen, uint8_t Cu)
{
	unsigned int len;

	len = MyMin(YLen, instance->Rsqueeze);
	Xoodyak_Up(instance, Y, len, Cu);
	Y += len;
	YLen -= len;
	while (YLen != 0) {
		Xoodyak_Down(instance, NULL, 0, 0);
		len = MyMin(YLen, instance->Rsqueeze);
		Xoodyak_Up(instance, Y, len, 0);
		Y += len;
		YLen -= len;
	}
}

void Xoodyak_Squeeze(Xoodyak_Instance* instance, uint8_t* Y, size_t YLen)
{
	Xoodyak_SqueezeAny(instance, Y, YLen, 0x40);
}
