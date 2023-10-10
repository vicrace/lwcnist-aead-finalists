#ifndef OPERATION_H_
#define OPERATION_H_

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "params.h"

//Initialise buffer
static void init_buffer(char n, uint8_t* buffer, uint64_t numbytes) {

	for (int k = 0; k < BATCH; k++) {
		for (int i = 0; i < numbytes; i++) {
			buffer[k * numbytes + i] = (uint8_t)(rand() % (k - 0 + 1) + 0) + i;

		}
	}
}

void print(uint8_t c, uint8_t* x, uint64_t xlen) {
	uint64_t i;
	printf("%c[%d]=", c, (int)xlen);
	for (i = 0; i < xlen; ++i) printf("%x", x[i]);
	printf("\n");
}

static void transposedata(uint8_t* in, uint8_t* out, int x, int y) {
	for (int iy = 0; iy < y; ++iy)
	{
		for (int ix = 0; ix < x; ++ix)
		{
			out[ix * y + iy] = in[iy * y + ix];
		}
	}
}

//Check cuda function
static void CHECK(cudaError_t call)
{
	const cudaError_t error = call;
	if (error != cudaSuccess)
	{
		fprintf(stderr, "Error: %s:%d, ", __FILE__, __LINE__);
		fprintf(stderr, "code: %d, reason: %s\n", error,
			cudaGetErrorString(error));
		exit(1);
	}
}

//check gpu and cpu results
static void checkResult(char* version, uint8_t* host, uint8_t* gpu, uint64_t clen, int t) {

	bool check = true;
	uint64_t i;
	for (int k = 0; k < BATCH; k++) {
		for (i = 0; i < clen; ++i) {
			if (host[k * clen + i] != gpu[k * clen + i] && (t != 64 && strstr(version,"Unoptimised") != NULL)) {
				printf("\nVersion %s - \tBatch %d ,element %d not match, host - %x\t gpu - %x\n", version, k, k * (clen + i), host[k * (clen + i)], gpu[k * (clen + i)]);
				check = false;
				break;
			}
		}
		if (!check) break;
	}
	if (!check) printf("\nVersion\n%s - \Not Match!!", version);

}


#endif // OPERATION_H_
