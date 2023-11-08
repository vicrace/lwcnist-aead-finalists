#ifndef PARAMS_H
#define PARAMS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16		// 128 bits - nonce
#define CRYPTO_KEYBYTES 16		// 128 bits - key
#define CRYPTO_ABYTES 16		// 128 bits - additional data
#define CRYPTO_NOOVERLAP 1
#define MAX_MESSAGE_LENGTH		32
#define MAX_ASSOCIATED_DATA_LENGTH	32
#define MAX_ASSOCIATED_DATA_LENGTH_8x4	16		//origin is 16

#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define DEBUG

//Variables
#define BATCH_SIZE				5
#define MLEN					MAX_MESSAGE_LENGTH
#define ALEN					MAX_ASSOCIATED_DATA_LENGTH
#define MAX_CIPHER_LENGTH		(MLEN + CRYPTO_ABYTES)
#define _TABLE_
#define fineLevel 4				//2,4,8,16
#define Tlimit 1024
//#define PRINT					// to print the key, nonce...
//#define PRINTC					// print cipher text
//#define WRITEFILE

//BEETLE PARAMS
#define RATE_INBITS 32
#define RATE_INBYTES ((RATE_INBITS + 7) / 8)

#define SQUEEZE_RATE_INBITS 128
#define SQUEEZE_RATE_INBYTES ((SQUEEZE_RATE_INBITS + 7) / 8)

#define CAPACITY_INBITS 224
#define CAPACITY_INBYTES ((CAPACITY_INBITS + 7) / 8)

#define STATE_INBITS (RATE_INBITS + CAPACITY_INBITS)
#define STATE_INBYTES ((STATE_INBITS + 7) / 8)

#define KEY_INBITS (CRYPTO_KEYBYTES * 8)
#define KEY_INBYTES (CRYPTO_KEYBYTES)

#define NOUNCE_INBITS (CRYPTO_NPUBBYTES * 8)
#define NOUNCE_INBYTES (CRYPTO_NPUBBYTES)

#define TAG_INBITS 128
#define TAG_INBYTES ((TAG_INBITS + 7) / 8)

#define LAST_THREE_BITS_OFFSET (STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3)

#define TAG_MATCH	 0
#define TAG_UNMATCH	-1
#define OTHER_FAILURES -2

#define ENC 0
#define DEC 1

#endif