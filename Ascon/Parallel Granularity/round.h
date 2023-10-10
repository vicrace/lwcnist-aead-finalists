#ifndef ROUND_H_
#define ROUND_H_

#include "params.h"
//#include "printstate.h"

static inline uint64_t ROR(uint64_t x, int n) {
	return x >> n | x << (-n & 63);
}

static inline void ROUND(state_t * s, uint8_t C) {
	state_t t;
	/* addition of round constant */
	s->x2 ^= C;
	/* printstate(" round constant", s); */
	/* substitution layer */
	s->x0 ^= s->x4;
	s->x4 ^= s->x3;
	s->x2 ^= s->x1;
	/* start of keccak s-box */
	t.x0 = s->x0 ^ (~s->x1 & s->x2);
	t.x1 = s->x1 ^ (~s->x2 & s->x3);
	t.x2 = s->x2 ^ (~s->x3 & s->x4);
	t.x3 = s->x3 ^ (~s->x4 & s->x0);
	t.x4 = s->x4 ^ (~s->x0 & s->x1);
	/* end of keccak s-box */
	t.x1 ^= t.x0;
	t.x0 ^= t.x4;
	t.x3 ^= t.x2;
	t.x2 = ~t.x2;
	/* printstate(" substitution layer", &t); */
	/* linear diffusion layer */
	s->x0 = t.x0 ^ ROR(t.x0, 19) ^ ROR(t.x0, 28);
	s->x1 = t.x1 ^ ROR(t.x1, 61) ^ ROR(t.x1, 39);
	s->x2 = t.x2 ^ ROR(t.x2, 1) ^ ROR(t.x2, 6);
	s->x3 = t.x3 ^ ROR(t.x3, 10) ^ ROR(t.x3, 17);
	s->x4 = t.x4 ^ ROR(t.x4, 7) ^ ROR(t.x4, 41);
	//printstate(" round output", s);
}


__device__ static inline uint64_t RORG(uint64_t x, int n) {
	return (x << (64 - n)) | (x >> n);
}

__device__ static inline void ROUNDG(state_t* s, uint8_t C) {
	state_t t;
	/* addition of round constant */
	s->x2 ^= C;
	/* printstate(" round constant", s); */
	/* substitution layer */
	s->x0 ^= s->x4;
	s->x4 ^= s->x3;
	s->x2 ^= s->x1;
	/* start of keccak s-box */
	t.x0 = s->x0 ^ (~s->x1 & s->x2);
	t.x1 = s->x1 ^ (~s->x2 & s->x3);
	t.x2 = s->x2 ^ (~s->x3 & s->x4);
	t.x3 = s->x3 ^ (~s->x4 & s->x0);
	t.x4 = s->x4 ^ (~s->x0 & s->x1);
	/* end of keccak s-box */
	t.x1 ^= t.x0;
	t.x0 ^= t.x4;
	t.x3 ^= t.x2;
	t.x2 = ~t.x2;
	/* printstate(" substitution layer", &t); */
	/* linear diffusion layer */
	s->x0 = t.x0 ^ RORG(t.x0, 19) ^ RORG(t.x0, 28);
	s->x1 = t.x1 ^ RORG(t.x1, 61) ^ RORG(t.x1, 39);
	s->x2 = t.x2 ^ RORG(t.x2, 1) ^ RORG(t.x2, 6);
	s->x3 = t.x3 ^ RORG(t.x3, 10) ^ RORG(t.x3, 17);
	s->x4 = t.x4 ^ RORG(t.x4, 7) ^ RORG(t.x4, 41);
	__syncthreads();
}
#endif /* ROUND_H_ */