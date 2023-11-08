#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "photon.h"
#include "params.h"

#define S				4
const byte ReductionPoly = 0x3;
const byte WORDFILTER = ((byte) 1<<S)-1;
int DEBUG = 0;

/* to be completed for one time pass mode */
unsigned long long MessBitLen = 0;

const byte RC[D][12] = {
	{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
	{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
	{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
	{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
	{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
	{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
	{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
	{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
};

const byte MixColMatrix[D][D] = {
	{ 2,  4,  2, 11,  2,  8,  5,  6},
	{12,  9,  8, 13,  7,  7,  5,  2},
	{ 4,  4, 13, 13,  9,  4, 13,  9},
	{ 1,  6,  5,  1, 12, 13, 15, 14},
	{15, 12,  9, 13, 14,  5, 14, 13},
	{ 9, 14,  5, 15,  4, 12,  9,  6},
	{12,  2,  2, 10,  3,  1,  1, 14},
	{15,  1, 13, 10,  5, 10,  2,  3}
};

byte sbox[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

byte FieldMult(byte a, byte b)
{
	byte x = a, ret = 0;
	int i;
	for(i = 0; i < S; i++) {
		if((b>>i)&1) ret ^= x;
		if((x>>(S-1))&1) {
			x <<= 1;
			x ^= ReductionPoly;
		}
		else x <<= 1;
	}
	return ret&WORDFILTER;
}

void PrintState(byte state[D][D])
{
	if(!DEBUG) return;
	int i, j;
	for(i = 0; i < D; i++){
		for(j = 0; j < D; j++)
			printf("%2X ", state[i][j]);
		printf("\n");
	}
	printf("\n");
}

void PrintState_Column(CWord state[D])
{
	if(!DEBUG) return;
	int i, j;
	for(i = 0; i < D; i++){
		for(j = 0; j < D; j++)
			printf("%2X ", (state[j]>>(i*S)) & WORDFILTER);
		printf("\n");
	}
	printf("\n");
}

void AddKey(byte state[D][D], int round)
{
	int i;
	for(i = 0; i < D; i++)
		state[i][0] ^= RC[i][round];
}

void SubCell(byte state[D][D])
{
	int i,j;
	for(i = 0; i < D; i++)
		for(j = 0; j <  D; j++)
			state[i][j] = sbox[state[i][j]];
}

void ShiftRow(byte state[D][D])
{
	int i, j;
	byte tmp[D];
	for(i = 1; i < D; i++) {
		for(j = 0; j < D; j++)
			tmp[j] = state[i][j];
		for(j = 0; j < D; j++)
			state[i][j] = tmp[(j+i)%D];
	}
}

void MixColumn(byte state[D][D])
{
	int i, j, k;
	byte tmp[D];
	for(j = 0; j < D; j++){
		for(i = 0; i < D; i++) {
			byte sum = 0;
			for(k = 0; k < D; k++)
				sum ^= FieldMult(MixColMatrix[i][k], state[k][j]);
			tmp[i] = sum;
		}
		for(i = 0; i < D; i++)
			state[i][j] = tmp[i];
	}
}


tword Table[D][1<<S];
void BuildTableSCShRMCS()
{
	int c, v, r;
	tword tv;
	for(v = 0; v < (1<<S); v++) {
		for(c = 0; c < D; c++){ // compute the entry Table[c][v]
			tv = 0;
			for(r = 0; r < D; r++){
				tv <<= S;
				tv |= (tword) FieldMult(MixColMatrix[r][c], sbox[v]);
			}
			Table[c][v] = tv;
		}
	}
	if(DEBUG){
		printf("tword Table[D][1<<S] = {\n");
		for(c = 0; c < D; c++){ 
			printf("\t{");
			for(v = 0; v < (1<<S); v++) {
				printf("0x%.8XU, ", Table[c][v]);
			}
			printf("}");
			if(v != (1<<S)-1) printf(",");
			printf("\n");
		}
		printf("};\n");
	}
}

void SCShRMCS(byte state[D][D])
{
	int c,r;
	tword v;
	byte os[D][D];
	memcpy(os, state, D*D);

	for(c = 0; c < D; c++){ // for all columns
		v = 0;
		for(r = 0; r < D; r++) // for all rows in this column i after ShiftRow
			v ^= Table[r][os[r][(r+c)%D]];

		for(r = 1; r <= D; r++){
			state[D-r][c] = (byte)v & WORDFILTER;
			v >>= S;
		}
	}
}


void Permutation(byte state[D][D], int R, int mode)
{
	int i;
	for(i = 0; i < R; i++) {
		if(DEBUG) printf("--- Round %d ---\n", i);
		AddKey(state, i); //PrintState(state);
		
		if(mode == 1)
			SCShRMCS(state);
		else {
			SubCell(state); PrintState(state);
			ShiftRow(state); PrintState(state);
			MixColumn(state);
		}
		
		//PrintState(state);
	}
}

void PHOTON_Permutation(unsigned char *State_in, int mode)
{
    byte state[D][D];
    int i;

	for (i = 0; i < D * D; i++)
	{
		state[i / D][i % D] = (State_in[i / 2] >> (4 * (i & 1))) & 0xf;
	}
   
    Permutation(state, ROUND, mode);

	memset(State_in, 0, (D * D) / 2);
	for (i = 0; i < D * D; i++)
	{
		State_in[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
	}
}




//For GPU

__device__ const byte RCG[D][12] = {
	{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
	{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
	{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
	{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
	{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
	{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
	{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
	{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
};

__device__ const byte MixColMatrixG[D][D] = {
	{ 2,  4,  2, 11,  2,  8,  5,  6},
	{12,  9,  8, 13,  7,  7,  5,  2},
	{ 4,  4, 13, 13,  9,  4, 13,  9},
	{ 1,  6,  5,  1, 12, 13, 15, 14},
	{15, 12,  9, 13, 14,  5, 14, 13},
	{ 9, 14,  5, 15,  4, 12,  9,  6},
	{12,  2,  2, 10,  3,  1,  1, 14},
	{15,  1, 13, 10,  5, 10,  2,  3}
};

__device__ byte sboxG[16] = { 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };

__device__ __constant__ uint32_t TableG[128] = { 0xbf5c86f8, 0xa9756b96, 0xceb643e4, 0x5dab3cd3, 0x1629ed6e, 0x0, 0x71eac51c, 0x931d7f37, 0x67c32872, 0xf4de5745, 0xd89fae8a, 0x3a6814a1, 0x85349259, 0xe2f7ba2b, 0x2c41f9cf, 0x4b82d1bd, 0x565ef4bc, 0x7b7d93a5, 0xb3b7e2c6, 0xacafd85b, 0x2d236719, 0x0, 0xe5e9167a, 0x1f183a9d, 0xc8ca7163, 0xd7d24bfe, 0x9e9485df, 0x6465a938, 0x323b5d84, 0xfaf12ce7, 0x4946ce21, 0x818cbf42, 0xba3969b3, 0xaec2b2ac, 0xc58d3dc8, 0x5761c156, 0x14fbdb1f, 0x0, 0x7fb4547b, 0x92ecfc9e, 0x6b4f8f64, 0xf9a373fa, 0xd176e6d7, 0x3c2e4e32, 0x86172781, 0xed58a8e5, 0x28d5952d, 0x439a1a49, 0xd33c3811, 0x1cc5c644, 0xf8868499, 0x966b6322, 0xcff9fe55, 0x0, 0x2bbabc88, 0x6eede7bb, 0xe44342dd, 0x8aaea566, 0x377f7acc, 0x722821ff, 0xa11419ee, 0x45575b33, 0xbdd1dfaa, 0x59929d77, 0xb26f4579, 0xa8b937f2, 0xc13e2bad, 0x54cd8ae1, 0x1ad6728b, 0x0, 0x73516ed4, 0x95f3a14c, 0x69871c5f, 0xfc74bd13, 0xdbe85926, 0x3d4a96be, 0x8f25d3c7, 0xe6a2cf98, 0x279ce435, 0x4e1bf86a, 0xa2539fc1, 0xe87c2954, 0x51b8de69, 0x74a61db2, 0x4a2fb695, 0x0, 0xf3eb41a8, 0x251ec3db, 0xb9c4f73d, 0x9cda34e6, 0x1b9768fc, 0xcd62ea8f, 0x6f31754e, 0xd6f58273, 0x874d5c1a, 0x3e89ab27, 0x993846cb, 0x22c63b5a, 0xdd84236c, 0x11638cb5, 0xbbfe7d91, 0x0, 0x44bc65a7, 0xcce7afd9, 0xff421836, 0x33a5b7ef, 0x667a5efd, 0xee219483, 0x7719d248, 0x885bca7e, 0x55dfe912, 0xaa9df124, 0xeb643e47, 0xdab3cd3f, 0x7c32872a, 0xf5c86f8e, 0x31d7f378, 0x0, 0x9756b96d, 0x89fae8a4, 0xa6814a15, 0x2f7ba2b1, 0x4de57452, 0x5349259b, 0xb82d1bdc, 0x1eac51c9, 0x629ed6e3, 0xc41f9cf6 };

__device__ byte FieldMultG(byte a, byte b)
{
	byte x = a, ret = 0;
	int i;
	for (i = 0; i < S; i++) {
		if ((b >> i) & 1) ret ^= x;
		if ((x >> (S - 1)) & 1) {
			x <<= 1;
			x ^= ReductionPoly;
		}
		else x <<= 1;
	}
	return ret & WORDFILTER;
}


__device__ void PrintStateG(byte state[D][D])
{
	//if (!DEBUG) return;
	int i, j;
	for (i = 0; i < D; i++) {
		for (j = 0; j < D; j++)
			printf("%2X ", state[i][j]);
		printf("\n");
	}
	printf("\n");
}

__device__ void PrintState_ColumnG(CWord state[D])
{
	//if (!DEBUG) return;
	int i, j;
	for (i = 0; i < D; i++) {
		for (j = 0; j < D; j++)
			printf("%2X ", (state[j] >> (i * S)) & WORDFILTER);
		printf("\n");
	}
	printf("\n");
}

__device__ void AddKeyG(byte state[D][D], int round)
{
	int i;
	for (i = 0; i < D; i++)
		state[i][0] ^= RCG[i][round];
}

__device__ void SubCellG(byte state[D][D])
{
	int i, j;
	for (i = 0; i < D; i++)
		for (j = 0; j < D; j++)
			state[i][j] = sboxG[state[i][j]];
}

__device__ void ShiftRowG(byte state[D][D])
{
	int i, j;
	byte tmp[D];
	for (i = 1; i < D; i++) {
		for (j = 0; j < D; j++)
			tmp[j] = state[i][j];
		for (j = 0; j < D; j++)
			state[i][j] = tmp[(j + i) % D];
	}
}

__device__ void MixColumnG(byte state[D][D])
{
	int i, j, k;
	byte tmp[D];
	for (j = 0; j < D; j++) {
		for (i = 0; i < D; i++) {
			byte sum = 0;
			for (k = 0; k < D; k++)
				sum ^= FieldMultG(MixColMatrixG[i][k], state[k][j]);
			tmp[i] = sum;
		}
		for (i = 0; i < D; i++)
			state[i][j] = tmp[i];
	}
}

//precomputed
__device__ void SCShRMCSG(byte state[D][D])
{
	int c, r;
	tword v;
	byte os[D][D];
	memcpy(os, state, D * D);

	for (c = 0; c < D; c++) { // for all columns
		v = 0;
		for (r = 0; r < D; r++) // for all rows in this column i after ShiftRow
			v ^= TableG[r * 16 + os[r][(r + c) % D]];

		for (r = 1; r <= D; r++) {
			state[D - r][c] = (byte)v & WORDFILTER;
			v >>= S;
		}
	}
}

__device__ void SCShRMCSG_Shared(byte state[D][D])
{
	int c, r, tid = threadIdx.x;
	uint32_t v;
	uint8_t os[D][D];
	memcpy(os, state, D * D); // wklee, optimize this later.

	__shared__ uint32_t stable[128];

	if (tid < 128) {
		stable[tid] = TableG[tid];
	}

	__syncthreads();

	//unroll
	for (c = 0; c < D; c++) { // for all columns	
		v = 0;

		v ^= stable[os[0][(0 + c) % D]];
		v ^= stable[1 * 16 + os[1][(1 + c) % D]];
		v ^= stable[2 * 16 + os[2][(2 + c) % D]];
		v ^= stable[3 * 16 + os[3][(3 + c) % D]];
		v ^= stable[4 * 16 + os[4][(4 + c) % D]];
		v ^= stable[5 * 16 + os[5][(5 + c) % D]];
		v ^= stable[6 * 16 + os[6][(6 + c) % D]];
		v ^= stable[7 * 16 + os[7][(7 + c) % D]];

		state[D - 1][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 2][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 3][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 4][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 5][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 6][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 7][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 8][c] = (uint8_t)v & WORDFILTER;	v >>= S;

	}
}

__device__ void SCShRMCSG_Shuffle(uint8_t state[D][D])
{
	int c, r, tid = threadIdx.x;
	uint32_t v, tb0, tb1, tb2, tb3;
	uint8_t os[D][D];
	memcpy(os, state, D * D); // wklee, optimize this later.

	tb0 = TableG[tid % 32];			tb1 = TableG[tid % 32 + 32];
	tb2 = TableG[tid % 32 + 64];	tb3 = TableG[tid % 32 + 96];

	//unroll
	for (c = 0; c < D; c++) { // for all columns	
		v = 0;

		v ^= __shfl_sync(0xffffffff, tb0, os[0][(0 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb0, 16 + os[1][(1 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb1, os[2][(2 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb1, 16 + os[3][(3 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb2, os[4][(4 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb2, 16 + os[5][(5 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb3, os[6][(6 + c) % D]);
		v ^= __shfl_sync(0xffffffff, tb3, 16 + os[7][(7 + c) % D]);

		state[D - 1][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 2][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 3][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 4][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 5][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 6][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 7][c] = (uint8_t)v & WORDFILTER;	v >>= S;
		state[D - 8][c] = (uint8_t)v & WORDFILTER;	v >>= S;

	}
	
}

__device__ void PermutationG(uint8_t state[D][D], int R, int mode)
{
	int i;
	for (i = 0; i < R; i++) {
		//if (DEBUG) printf("--- Round %d ---\n", i);
		AddKeyG(state, i); //PrintStateG(state);

		if (mode == 2)
			SCShRMCSG(state);
		else if (mode == 3)
			SCShRMCSG_Shared(state);
		else if (mode == 4)
			SCShRMCSG_Shuffle(state);
		else {
			SubCellG(state); //PrintStateG(state);
			ShiftRowG(state); //PrintStateG(state);
			MixColumnG(state);
		}
		//PrintStateG(state);
	}
}

__device__ void PHOTON_PermutationG(unsigned char* State_in, int mode)
{
	uint8_t state[D][D];
	int i;

	for (i = 0; i < D * D; i++)
	{
		state[i / D][i % D] = (State_in[i / 2] >> (4 * (i & 1))) & 0xf;
	}

	PermutationG(state, ROUND, mode);

	memset(State_in, 0, (D * D) / 2);
	for (i = 0; i < D * D; i++)
	{
		State_in[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
	}
}