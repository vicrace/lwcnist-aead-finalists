#ifndef PARAMS_H
#define PARAMS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// ASCON 128
#define CRYPTO_VERSION "1.2.6"
#define CRYPTO_KEYBYTES 16												//Key = 16 bytes , 128 bits
#define CRYPTO_NSECBYTES 0	
#define CRYPTO_NPUBBYTES 16												//Nonce 16 bytes , 128 bits
#define CRYPTO_ABYTES 16												//AD	16 bytes , 128 bits
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 8												//Data size 8 bytes, 64 bits per operation
#define MAX_MESSAGE_LENGTH 32											// Maximum message length
#define MAX_ASSOCIATED_DATA_LENGTH 32									// Max AD length

// GPU
#define BATCH_SIZE 5

// Param
#define OFFSET(arr,i,offset) (arr + (i*offset))							// To find offset in CPU to match with GPU.
#define MLEN MAX_MESSAGE_LENGTH											//Message length 8			, max is 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH									//Additional length 8		, max is 32
#define MAX_CIPHER_LENGTH	(MLEN + CRYPTO_ABYTES)						// Max ciphertext length - message length

//#define WRITEFILE														//save data in CSV

typedef struct {
	uint64_t x0, x1, x2, x3, x4;
} state_t;
#endif