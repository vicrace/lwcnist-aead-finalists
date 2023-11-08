#include "params.h"
#include "photon.h"

/* Declaration of basic internal functions */
static uint8_t selectConst(
	const bool condition1,
	const bool condition2,
	const uint8_t option1,
	const uint8_t option2,
	const uint8_t option3,
	const uint8_t option4);
	
static void concatenate(
	uint8_t *out,
	const uint8_t *in_left, const size_t leftlen_inbytes,
	const uint8_t *in_right, const size_t rightlen_inbytes);

static void XOR(
	uint8_t *out,
	const uint8_t *in_left,
	const uint8_t *in_right,
	const size_t iolen_inbytes);

static void XOR_const(
	uint8_t *State_inout,
	const uint8_t  Constant);

static void ROTR1(
	uint8_t *out,
	const uint8_t *in,
	const size_t iolen_inbytes);

static void ShuffleXOR(
	uint8_t *DataBlock_out,
	const uint8_t *OuterState_in,
	const uint8_t *DataBlock_in,
	const size_t DBlen_inbytes);
	
static void rhoohr(
	uint8_t *OuterState_inout,
	uint8_t *DataBlock_out,
	const uint8_t *DataBlock_in,
	const size_t DBlen_inbytes,
	const uint32_t EncDecInd);

static void HASH(
	uint8_t *State_inout,
	const uint8_t *Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t  Constant);

static void ENCorDEC(
	uint8_t *State_inout,
	uint8_t *Data_out,
	const uint8_t *Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t Constant,
	const uint32_t EncDecInd);

static void TAG(
	uint8_t *Tag_out,
	uint8_t *State);

/* Definition of basic internal functions */
static uint8_t selectConst(
	const bool condition1,
	const bool condition2,
	const uint8_t option1,
	const uint8_t option2,
	const uint8_t option3,
	const uint8_t option4)
{
	if (condition1 && condition2) return option1;
	if (condition1) return option2;
	if (condition2) return option3;
	return option4;
}

static void concatenate(
	uint8_t *out,
	const uint8_t *in_left, const size_t leftlen_inbytes,
	const uint8_t *in_right, const size_t rightlen_inbytes)
{
	memcpy(out, in_left, leftlen_inbytes);
	memcpy(out + leftlen_inbytes, in_right, rightlen_inbytes);
}

static void XOR(
	uint8_t *out,
	const uint8_t *in_left,
	const uint8_t *in_right,
	const size_t iolen_inbytes)
{
	size_t i;
	for (i = 0; i < iolen_inbytes; i++) out[i] = in_left[i] ^ in_right[i];
}

static void XOR_const(
	uint8_t *State_inout,
	const uint8_t  Constant)
{
	State_inout[STATE_INBYTES - 1] ^= (Constant << LAST_THREE_BITS_OFFSET);
}

static void ROTR1(
	uint8_t *out,
	const uint8_t *in,
	const size_t iolen_inbytes)
{
	uint8_t tmp = in[0];
	size_t i;
	for (i = 0; i < iolen_inbytes - 1; i++)
	{
		out[i] = (in[i] >> 1) | ((in[(i+1)] & 1) << 7);
	}
	out[iolen_inbytes - 1] = (in[i] >> 1) | ((tmp & 1) << 7);
}

static void ShuffleXOR(
	uint8_t *DataBlock_out,
	const uint8_t *OuterState_in,
	const uint8_t *DataBlock_in,
	const size_t DBlen_inbytes)
{
	const uint8_t *OuterState_part1 = OuterState_in;
	const uint8_t *OuterState_part2 = OuterState_in + RATE_INBYTES / 2;

	uint8_t OuterState_part1_ROTR1[RATE_INBYTES / 2] = { 0 };
	size_t i;

	ROTR1(OuterState_part1_ROTR1, OuterState_part1, RATE_INBYTES / 2);

	i = 0;
	while ((i < DBlen_inbytes) && (i < RATE_INBYTES / 2))
	{
		DataBlock_out[i] = OuterState_part2[i] ^ DataBlock_in[i];
		i++;
	}
	while (i < DBlen_inbytes)
	{
		DataBlock_out[i] = OuterState_part1_ROTR1[i - RATE_INBYTES / 2] ^ DataBlock_in[i];
		i++;
	}
}

static void rhoohr(
	uint8_t *OuterState_inout,
	uint8_t *DataBlock_out,
	const uint8_t *DataBlock_in,
	const size_t DBlen_inbytes,
	const uint32_t EncDecInd)
{
	ShuffleXOR(DataBlock_out, OuterState_inout, DataBlock_in, DBlen_inbytes);

	if (EncDecInd == ENC)
	{
		XOR(OuterState_inout, OuterState_inout, DataBlock_in, DBlen_inbytes);
	}
	else
	{
		XOR(OuterState_inout, OuterState_inout, DataBlock_out, DBlen_inbytes);
	}	
}

static void HASH(
	uint8_t *State_inout,
	const uint8_t *Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t  Constant)
{
	uint8_t *State = State_inout;
	size_t Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
	size_t LastDBlocklen;
	size_t i;

	for (i = 0; i < Dlen_inblocks - 1; i++)
	{
		PHOTON_Permutation(State);
		XOR(State, State, Data_in + i * RATE_INBYTES, RATE_INBYTES);
	}
	PHOTON_Permutation(State);	
	LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
	XOR(State, State, Data_in + i * RATE_INBYTES, LastDBlocklen);
	if (LastDBlocklen < RATE_INBYTES) State[LastDBlocklen] ^= 0x01; // ozs

	XOR_const(State, Constant);
}

static void ENCorDEC(
	uint8_t *State_inout,
	uint8_t *Data_out,
	const uint8_t *Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t Constant,
	const uint32_t EncDecInd)
{
	uint8_t *State = State_inout;
	size_t Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
	size_t LastDBlocklen;
	size_t i;

	for (i = 0; i < Dlen_inblocks - 1; i++)
	{
		PHOTON_Permutation(State);
		rhoohr(State, Data_out + i * RATE_INBYTES, Data_in + i * RATE_INBYTES, RATE_INBYTES, EncDecInd);
	}
	PHOTON_Permutation(State);
	LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
	rhoohr(State, Data_out + i * RATE_INBYTES, Data_in + i * RATE_INBYTES, LastDBlocklen, EncDecInd);
	if (LastDBlocklen < RATE_INBYTES) State[LastDBlocklen] ^= 0x01; // ozs

	XOR_const(State, Constant);
}

static void TAG(
	uint8_t *Tag_out,
	uint8_t *State)
{
	size_t i;

	i = TAG_INBYTES;
	while (i > SQUEEZE_RATE_INBYTES)
	{
		PHOTON_Permutation(State);
		memcpy(Tag_out, State, SQUEEZE_RATE_INBYTES);
		Tag_out += SQUEEZE_RATE_INBYTES;
		i -= SQUEEZE_RATE_INBYTES;
	}
	PHOTON_Permutation(State);
	memcpy(Tag_out, State, i);
}

/* Functions for GPU */
__device__ uint8_t selectConstG(
	const bool condition1,
	const bool condition2,
	const uint8_t option1,
	const uint8_t option2,
	const uint8_t option3,
	const uint8_t option4)
{
	if (condition1 && condition2) return option1;
	if (condition1) return option2;
	if (condition2) return option3;
	return option4;
}

__device__ void concatenateG(
	uint8_t* out,
	const uint8_t* in_left, const size_t leftlen_inbytes,
	const uint8_t* in_right, const size_t rightlen_inbytes)
{
	memcpy(out, in_left, leftlen_inbytes);
	memcpy(out + leftlen_inbytes, in_right, rightlen_inbytes);
}

__device__ void XORG(
	uint8_t* out,
	const uint8_t* in_left,
	const uint8_t* in_right,
	const size_t iolen_inbytes)
{
	size_t i;
	for (i = 0; i < iolen_inbytes; i++) out[i] = in_left[i] ^ in_right[i];
}

__device__ void XOR_constG(
	uint8_t* State_inout,
	const uint8_t  Constant)
{
	State_inout[STATE_INBYTES - 1] ^= (Constant << LAST_THREE_BITS_OFFSET);
}

__device__ void ROTR1G(
	uint8_t* out,
	const uint8_t* in,
	const size_t iolen_inbytes)
{
	uint8_t tmp = in[0];
	size_t i;
	for (i = 0; i < iolen_inbytes - 1; i++)
	{
		out[i] = (in[i] >> 1) | ((in[(i + 1)] & 1) << 7);
	}
	out[iolen_inbytes - 1] = (in[i] >> 1) | ((tmp & 1) << 7);
}

__device__ void ShuffleXORG(
	uint8_t* DataBlock_out,
	const uint8_t* OuterState_in,
	const uint8_t* DataBlock_in,
	const size_t DBlen_inbytes)
{
	const uint8_t* OuterState_part1 = OuterState_in;
	const uint8_t* OuterState_part2 = OuterState_in + RATE_INBYTES / 2;

	uint8_t OuterState_part1_ROTR1[RATE_INBYTES / 2] = { 0 };
	size_t i;

	ROTR1G(OuterState_part1_ROTR1, OuterState_part1, RATE_INBYTES / 2);

	i = 0;
	while ((i < DBlen_inbytes) && (i < RATE_INBYTES / 2))
	{
		DataBlock_out[i] = OuterState_part2[i] ^ DataBlock_in[i];
		i++;
	}
	while (i < DBlen_inbytes)
	{
		DataBlock_out[i] = OuterState_part1_ROTR1[i - RATE_INBYTES / 2] ^ DataBlock_in[i];
		i++;
	}
}

__device__ void rhoohrG(
	uint8_t* OuterState_inout,
	uint8_t* DataBlock_out,
	const uint8_t* DataBlock_in,
	const size_t DBlen_inbytes,
	const uint32_t EncDecInd)
{
	ShuffleXORG(DataBlock_out, OuterState_inout, DataBlock_in, DBlen_inbytes);

	if (EncDecInd == ENC)
	{
		XORG(OuterState_inout, OuterState_inout, DataBlock_in, DBlen_inbytes);
	}
	else
	{
		XORG(OuterState_inout, OuterState_inout, DataBlock_out, DBlen_inbytes);
	}
}

__device__ void HASHG(
	uint8_t* State_inout,
	const uint8_t* Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t  Constant)
{
	uint8_t* State = State_inout;
	size_t Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
	size_t LastDBlocklen;
	size_t i;

	for (i = 0; i < Dlen_inblocks - 1; i++)
	{
		PHOTON_PermutationG(State);
		XORG(State, State, Data_in + i * RATE_INBYTES, RATE_INBYTES);
	}
	PHOTON_PermutationG(State);
	LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
	XORG(State, State, Data_in + i * RATE_INBYTES, LastDBlocklen);
	if (LastDBlocklen < RATE_INBYTES) State[LastDBlocklen] ^= 0x01; // ozs

	XOR_constG(State, Constant);
}

__device__ void ENCorDECG(
	uint8_t* State_inout,
	uint8_t* Data_out,
	const uint8_t* Data_in,
	const uint64_t Dlen_inbytes,
	const uint8_t Constant,
	const uint32_t EncDecInd)
{
	uint8_t* State = State_inout;
	size_t Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
	size_t LastDBlocklen;
	size_t i;

	for (i = 0; i < Dlen_inblocks - 1; i++)
	{
		PHOTON_PermutationG(State);
		rhoohrG(State, Data_out + i * RATE_INBYTES, Data_in + i * RATE_INBYTES, RATE_INBYTES, EncDecInd);
	}
	PHOTON_PermutationG(State);
	LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
	rhoohrG(State, Data_out + i * RATE_INBYTES, Data_in + i * RATE_INBYTES, LastDBlocklen, EncDecInd);
	if (LastDBlocklen < RATE_INBYTES) State[LastDBlocklen] ^= 0x01; // ozs

	XOR_constG(State, Constant);
}

__device__ void TAGG(
	uint8_t* Tag_out,
	uint8_t* State)
{
	size_t i;

	i = TAG_INBYTES;
	while (i > SQUEEZE_RATE_INBYTES)
	{
		PHOTON_PermutationG(State);
		memcpy(Tag_out, State, SQUEEZE_RATE_INBYTES);
		Tag_out += SQUEEZE_RATE_INBYTES;
		i -= SQUEEZE_RATE_INBYTES;
	}
	PHOTON_PermutationG(State);
	memcpy(Tag_out, State, i);
}