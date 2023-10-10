// GPU
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH	16000000	//64000
//#define WRITEFILE

#define ISAP_rH 64
//#define ISAP_rB 1
// Security level
//#define ISAP_K 128

// Number of rounds
#define ISAP_sH 12
#define ISAP_sB 12
#define ISAP_sE 12
#define ISAP_sK 12

// State size in bytes
#define ISAP_STATE_SZ 40

// Size of rate in bytes
#define ISAP_rH_SZ ((ISAP_rH+7)/8)

// Size of zero truncated IV in bytes
#define ISAP_IV_SZ 8


// Size of tag in bytes
#define ISAP_TAG_SZ 16
