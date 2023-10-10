// GPU
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 12
#define CRYPTO_ABYTES_S 8	//Spongent - 176
#define CRYPTO_ABYTES_K 16  //Keccak - 200
#define CRYPTO_NOOVERLAP 1

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH(LEN) (MLEN + LEN)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH	16000000		//64000, for testing
#define Tlimit 1025 
#define fineLevel 2 //Change Fine Level between 2 / 4 / 8

typedef unsigned char BYTE;

// Spongent 176
#define BLOCK_SIZE_S 22
#define nBits		176
#define nSBox		22
#define nRounds		90
#define lfsrIV	    0x45
#define GET_BIT(x,y) (x >> y) & 0x1


//Keccak 200
#define BLOCK_SIZE_K 25
#define maxNrRounds 18
#define nrLanes 25
#define index(x, y) (((x)%5)+5*((y)%5))
#define ROL8(a, offset) ((offset != 0) ? ((((BYTE)a) << offset) ^ (((BYTE)a) >> (sizeof(BYTE)*8-offset))) : a)
