/*
	 TinyJAMBU-128: 128-bit key, 96-bit IV
	 Reference implementation for 32-bit CPU
	 The state consists of four 32-bit registers
	 state[3] || state[2] || state[1] || state[0]
*/

#include "params.h"

/*************************************************************************************/
/*                                                                                   */
/*                                          CPU                                      */
/*                                                                                   */
/*************************************************************************************/

void state_update_Ref(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	unsigned int i;
	unsigned int t1, t2, t3, t4, feedback;
	for (i = 0; i < (number_of_steps >> 5); i++)
	{
		t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
		t2 = (state[2] >> 6) | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		feedback = state[0] ^ t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 3];
		// shift 32 bit positions 
		state[0] = state[1]; state[1] = state[2]; state[2] = state[3];
		state[3] = feedback;
	}
}

/*optimized state update function*/
void state_update_OpRef(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	unsigned int i;
	unsigned int t1, t2, t3, t4;

	//in each iteration, we compute 128 rounds of the state update function. 
	for (i = 0; i < number_of_steps; i = i + 128)
	{
		t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
		t2 = (state[2] >> 6) | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		state[0] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[0];

		t1 = (state[2] >> 15) | (state[3] << 17);
		t2 = (state[3] >> 6) | (state[0] << 26);
		t3 = (state[3] >> 21) | (state[0] << 11);
		t4 = (state[3] >> 27) | (state[0] << 5);
		state[1] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[1];

		t1 = (state[3] >> 15) | (state[0] << 17);
		t2 = (state[0] >> 6) | (state[1] << 26);
		t3 = (state[0] >> 21) | (state[1] << 11);
		t4 = (state[0] >> 27) | (state[1] << 5);
		state[2] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[2];

		t1 = (state[0] >> 15) | (state[1] << 17);
		t2 = (state[1] >> 6) | (state[2] << 26);
		t3 = (state[1] >> 21) | (state[2] << 11);
		t4 = (state[1] >> 27) | (state[2] << 5);
		state[3] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[3];
	}
}

void initialization_CPU(const unsigned char* key, const unsigned char* iv, unsigned int* state, unsigned int v)
{
	int i;

	//initialize the state as 0  
	for (i = 0; i < 4; i++) state[i] = 0;

	//update the state with the key  
	if (v == 0) state_update_Ref(state, key, NROUND2); else state_update_OpRef(state, key, NROUND2);

	//introduce IV into the state  
	for (i = 0; i < 3; i++)
	{
		state[1] ^= FrameBitsIV;
		if (v == 0) state_update_Ref(state, key, NROUND1); else state_update_OpRef(state, key, NROUND1);
		state[3] ^= ((unsigned int*)iv)[i];
	}
}

void process_ad_CPU(const unsigned char* k, const unsigned char* ad, unsigned long long adlen, unsigned int* state, unsigned int v)
{
	unsigned long long i;
	unsigned int j;

	for (i = 0; i < (adlen >> 2); i++)
	{
		state[1] ^= FrameBitsAD;
		if (v == 0) state_update_Ref(state, k, NROUND1); else state_update_OpRef(state, k, NROUND1);
		state[3] ^= ((unsigned int*)ad)[i];
	}

	// if adlen is not a multiple of 4, we process the remaining bytes
	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		if (v == 0) state_update_Ref(state, k, NROUND1); else state_update_OpRef(state, k, NROUND1);
		for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}
}

/*************************************************************************************/
/*                                                                                   */
/*                                       GPU                                         */
/*                                                                                   */
/*************************************************************************************/

/*****************************     ******************************/
/*							  Ref								*/
/*****************************     ******************************/


__device__ void state_update_RefG(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	unsigned int i;
	unsigned int t1, t2, t3, t4, feedback;
#pragma unroll
	for (i = 0; i < (number_of_steps >> 5); i++)
	{
		t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
		t2 = (state[2] >> 6) | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		feedback = state[0] ^ t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 3];
		// shift 32 bit positions 
		state[0] = state[1]; state[1] = state[2]; state[2] = state[3];
		state[3] = feedback;
	}
}

__device__ void initialization_GPU(const unsigned char* key, const unsigned char* iv, unsigned int* state)
{
	int i;

	//initialize the state as 0  
	for (i = 0; i < 4; i++) state[i] = 0;

	//update the state with the key  
	state_update_RefG(state, key, NROUND2);

	//introduce IV into the state  
	for (i = 0; i < 3; i++)
	{
		state[1] ^= FrameBitsIV;
		state_update_RefG(state, key, NROUND1);
		state[3] ^= ((unsigned int*)iv)[i];
	}
}

__device__ void process_ad_GPU(const unsigned char* k, const unsigned char* ad, unsigned long long adlen, unsigned int* state)
{
	unsigned long long i;
	unsigned int j;

#pragma unroll
	for (i = 0; i < (adlen >> 2); i++)
	{
		state[1] ^= FrameBitsAD;
		state_update_RefG(state, k, NROUND1);
		state[3] ^= ((unsigned int*)ad)[i];
	}

	// if adlen is not a multiple of 4, we process the remaining bytes
	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		state_update_RefG(state, k, NROUND1);
		for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}
}

/*****************************     ******************************/
/*							Op  Ref								*/
/*****************************     ******************************/

/*optimized state update function*/
__device__ void state_update_OpRefG(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	unsigned int i;
	unsigned int t1, t2, t3, t4;
	//in each iteration, we compute 128 rounds of the state update function. 
#pragma unroll
	for (i = 0; i < number_of_steps; i = i + 128)
	{
		t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
		t2 = (state[2] >> 6) | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		state[0] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[0];

		t1 = (state[2] >> 15) | (state[3] << 17);
		t2 = (state[3] >> 6) | (state[0] << 26);
		t3 = (state[3] >> 21) | (state[0] << 11);
		t4 = (state[3] >> 27) | (state[0] << 5);
		state[1] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[1];

		t1 = (state[3] >> 15) | (state[0] << 17);
		t2 = (state[0] >> 6) | (state[1] << 26);
		t3 = (state[0] >> 21) | (state[1] << 11);
		t4 = (state[0] >> 27) | (state[1] << 5);
		state[2] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[2];

		t1 = (state[0] >> 15) | (state[1] << 17);
		t2 = (state[1] >> 6) | (state[2] << 26);
		t3 = (state[1] >> 21) | (state[2] << 11);
		t4 = (state[1] >> 27) | (state[2] << 5);
		state[3] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[3];
	}
}

__device__ void initialization_OpGPU(const unsigned char* key, const unsigned char* iv, unsigned int* state)
{
	int i;

	//initialize the state as 0  
	for (i = 0; i < 4; i++) state[i] = 0;

	//update the state with the key  
	state_update_OpRefG(state, key, NROUND2);

	//introduce IV into the state  
	for (i = 0; i < 3; i++)
	{
		state[1] ^= FrameBitsIV;
		state_update_OpRefG(state, key, NROUND1);
		state[3] ^= ((unsigned int*)iv)[i];
	}
}

__device__ void process_ad_OpGPU(const unsigned char* k, const unsigned char* ad, unsigned long long adlen, unsigned int* state)
{
	unsigned long long i;
	unsigned int j;

#pragma unroll
	for (i = 0; i < (adlen >> 2); i++)
	{
		state[1] ^= FrameBitsAD;
		state_update_OpRefG(state, k, NROUND1);
		state[3] ^= ((unsigned int*)ad)[i];
	}

	// if adlen is not a multiple of 4, we process the remaining bytes
	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		state_update_OpRefG(state, k, NROUND1);
		for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}
}

/*****************************     ******************************/
/*							    Op Register 					*/
/*****************************     ******************************/

__device__ void state_update_OpRef_Register(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	unsigned int i;
	unsigned int t1, t2, t3, t4, feedback;
	unsigned int state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3];

	//in each iteration, we compute 128 rounds of the state update function. 

	for (i = 0; i < (number_of_steps >> 5); i++)
	{
		t1 = (state1 >> 15) | (state2 << 17);  // 47 = 1*32+15 
		t2 = (state2 >> 6) | (state3 << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state2 >> 21) | (state3 << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state2 >> 27) | (state3 << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		feedback = state0 ^ t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 3];
		// shift 32 bit positions 
		state0 = state1; state1 = state2; state2 = state3;
		state3 = feedback;
	}

	state[0] = state0, state[1] = state1, state[2] = state2, state[3] = state3;
}

__device__ void initialization_GPU_Op(const unsigned char* K, const unsigned char* iv, unsigned int* state)
{
	int i;

	//initialize the state as 0  
	for (i = 0; i < 4; i++) state[i] = 0;

	//update the state with the key  (K, number_of_steps)
	state_update_OpRef_Register(state, K, NROUND2);

	//introduce IV into the state  
	for (i = 0; i < 3; i++)
	{
		state[1] ^= FrameBitsIV;
		state_update_OpRef_Register(state, K, NROUND1);
		state[3] ^= ((unsigned int*)iv)[i];
	}
}

__device__ void process_ad_GPU_Op(const unsigned char* k, const unsigned char* ad, unsigned long long adlen, unsigned int* state)
{
	unsigned long long i;
	unsigned int j;

	for (i = 0; i < (adlen >> 2); i ++)
	{
		state[1] ^= FrameBitsAD;
		state_update_OpRef_Register(state, k, NROUND1);
		state[3] ^= ((unsigned int*)ad)[i];
	}

	// if adlen is not a multiple of 4, we process the remaining bytes
	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		state_update_OpRef_Register(state, k, NROUND1);
		for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}
}

/*****************************     ******************************/
/*						   Op Key inversion						*/
/*****************************     ******************************/

/*optimized state update function*/
__device__ void state_update_Op_Key(unsigned int* state, const unsigned char* key, unsigned int number_of_steps)
{
	//unsigned int i;
	//unsigned int t1, t2, t3, t4, feedback;
	//unsigned int state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3];

	//for (i = 0; i < (number_of_steps >> 5); i++)
	//{
	//	t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
	//	t2 = (state[2] >> 6) | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
	//	t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
	//	t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
	//	feedback = state[0] ^ t1 ^ ((t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 3];
	//	// shift 32 bit positions 
	//	state[0] = state[1]; state[1] = state[2]; state[2] = state[3];
	//	state[3] = feedback;
	//}
	unsigned int i;
	unsigned int t1, t2, t3, t4, feedback;
	unsigned int state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3];

	//in each iteration, we compute 128 rounds of the state update function. 

	for (i = 0; i < (number_of_steps >> 5); i++)
	{
		t1 = (state1 >> 15) | (state2 << 17);  // 47 = 1*32+15 
		t2 = (state2 >> 6) | (state3 << 26);  // 47 + 23 = 70 = 2*32 + 6 
		t3 = (state2 >> 21) | (state3 << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
		t4 = (state2 >> 27) | (state3 << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
		feedback = state0 ^ t1 ^ ((t2 & t3)) ^ t4 ^ ((unsigned int*)key)[i & 3];
		// shift 32 bit positions 
		state0 = state1; state1 = state2; state2 = state3;
		state3 = feedback;
	}

	state[0] = state0, state[1] = state1, state[2] = state2, state[3] = state3;
}


__device__ void initialization_OpGPU_Key(const unsigned char* K, const unsigned char* iv, unsigned int* state)
{
	int i;

	//initialize the state as 0  
	for (i = 0; i < 4; i++) state[i] = 0;

	//update the state with the key  (K, number_of_steps)
	state_update_Op_Key(state, K, NROUND2);

	//introduce IV into the state  
	for (i = 0; i < 3; i++)
	{
		state[1] ^= FrameBitsIV;
		state_update_Op_Key(state, K, NROUND1);
		state[3] ^= ((unsigned int*)iv)[i];
	}
}

__device__ void process_ad_OpGPU_Key(const unsigned char* k, const unsigned char* ad, unsigned long long adlen, unsigned int* state)
{
	unsigned long long i;
	unsigned int j;

	for (i = 0; i < (adlen >> 2); i++)
	{
		state[1] ^= FrameBitsAD;
		state_update_Op_Key(state, k, NROUND1);
		state[3] ^= ((unsigned int*)ad)[i];
	}

	// if adlen is not a multiple of 4, we process the remaining bytes
	if ((adlen & 3) > 0)
	{
		state[1] ^= FrameBitsAD;
		state_update_Op_Key(state, k, NROUND1);
		for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
		state[1] ^= adlen & 3;
	}
}