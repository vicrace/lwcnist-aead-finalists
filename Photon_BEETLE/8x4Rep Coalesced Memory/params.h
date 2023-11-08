#ifndef PARAMS_H
#define PARAMS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16		// 128 bits - nonce					//origin is 16ul
#define CRYPTO_KEYBYTES 16		// 128 bits - key					//origin is 16ul
#define CRYPTO_ABYTES 16		// 128 bits - additional data
#define CRYPTO_NOOVERLAP 1
#define MAX_MESSAGE_LENGTH		32			//origin is 64
#define MAX_ASSOCIATED_DATA_LENGTH	16		//origin is 16
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define DEBUG

#if defined(_MSC_VER)
#define ENDIAN 1			//little endian
#elif 
#define ENDIAN 0			//big endian
#endif

//Variables
//#define BATCH					1*32*32	///iterations
#define BATCH					16000000 //64000
#define MLEN					MAX_MESSAGE_LENGTH
#define ALEN					MAX_ASSOCIATED_DATA_LENGTH
#define MAX_CIPHER_LENGTH		MLEN
//#define PRINT					// to print the key, nonce...
//#define PRINTC					// print cipher text
#define R	4	//16 for Photon-Beetle-AEAD-128 / 4 for AEAD-32 bit rate of bytes

#endif