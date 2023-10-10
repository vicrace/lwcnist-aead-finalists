// GPU
#define CRYPTO_KEYBYTES     16
#define CRYPTO_NSECBYTES    0
#define CRYPTO_NPUBBYTES    16
#define CRYPTO_ABYTES       16
#define CRYPTO_NOOVERLAP    1
#define COFB_ENCRYPT 1		// 1 is encrypt , 0 is decrypt

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH 16000000
#define NSTREAM_SIZE 5

typedef unsigned char block[16];
typedef unsigned char half_block[8];