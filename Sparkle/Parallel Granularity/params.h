// GPU
#define CRYPTO_KEYBYTES 32
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 32
#define CRYPTO_ABYTES 32
#define CRYPTO_NOOVERLAP 1

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH_SIZE	5
#define SCHWAEMM256_256

/*************************/
/*		  Version        */
///////////////////////////
#if defined SCHWAEMM128_128
///////////////////////////

#define SCHWAEMM_KEY_LEN    128
#define SCHWAEMM_NONCE_LEN  128
#define SCHWAEMM_TAG_LEN    128

#define SPARKLE_STATE       256
#define SPARKLE_RATE        128
#define SPARKLE_CAPACITY    128

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   10


/////////////////////////////
#elif defined SCHWAEMM256_128
/////////////////////////////

#define SCHWAEMM_KEY_LEN    128
#define SCHWAEMM_NONCE_LEN  256
#define SCHWAEMM_TAG_LEN    128

#define SPARKLE_STATE       384
#define SPARKLE_RATE        256
#define SPARKLE_CAPACITY    128

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   11


/////////////////////////////
#elif defined SCHWAEMM192_192
/////////////////////////////

#define SCHWAEMM_KEY_LEN    192
#define SCHWAEMM_NONCE_LEN  192
#define SCHWAEMM_TAG_LEN    192

#define SPARKLE_STATE       384
#define SPARKLE_RATE        192
#define SPARKLE_CAPACITY    192

#define SPARKLE_STEPS_SLIM  7
#define SPARKLE_STEPS_BIG   11


/////////////////////////////
#elif defined SCHWAEMM256_256
/////////////////////////////

#define SCHWAEMM_KEY_LEN    256
#define SCHWAEMM_NONCE_LEN  256
#define SCHWAEMM_TAG_LEN    256

#define SPARKLE_STATE       512
#define SPARKLE_RATE        256
#define SPARKLE_CAPACITY    256

#define SPARKLE_STEPS_SLIM  8
#define SPARKLE_STEPS_BIG   12

#endif


/*************************/
/*		  Unop Func      */
/*************************/

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ELL(x) (ROT(((x) ^ ((x) << 16)), 16))


// 4-round ARX-box
#define ARXBOX(x, y, c)                     \
  (x) += ROT((y), 31), (y) ^= ROT((x), 24), \
  (x) ^= (c),                               \
  (x) += ROT((y), 17), (y) ^= ROT((x), 17), \
  (x) ^= (c),                               \
  (x) += (y),          (y) ^= ROT((x), 31), \
  (x) ^= (c),                               \
  (x) += ROT((y), 24), (y) ^= ROT((x), 16), \
  (x) ^= (c)


// Inverse of 4-round ARX-box
#define ARXBOX_INV(x, y, c)                 \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 16), (x) -= ROT((y), 24), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 31), (x) -= (y),          \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 17), (x) -= ROT((y), 17), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 24), (x) -= ROT((y), 31)


typedef unsigned char UChar;
typedef unsigned long long int ULLInt;

#define KEY_WORDS   (SCHWAEMM_KEY_LEN/32)
#define KEY_BYTES   (SCHWAEMM_KEY_LEN/8)
#define NONCE_WORDS (SCHWAEMM_NONCE_LEN/32)
#define NONCE_BYTES (SCHWAEMM_NONCE_LEN/8)
#define TAG_WORDS   (SCHWAEMM_TAG_LEN/32)
#define TAG_BYTES   (SCHWAEMM_TAG_LEN/8)

#define STATE_BRANS (SPARKLE_STATE/64)
#define STATE_WORDS (SPARKLE_STATE/32)
#define STATE_BYTES (SPARKLE_STATE/8)
#define RATE_BRANS  (SPARKLE_RATE/64)
#define RATE_WORDS  (SPARKLE_RATE/32)
#define RATE_BYTES  (SPARKLE_RATE/8)
#define CAP_BRANS   (SPARKLE_CAPACITY/64)
#define CAP_WORDS   (SPARKLE_CAPACITY/32)
#define CAP_BYTES   (SPARKLE_CAPACITY/8)

#define CONST_A0 (((uint32_t) (0 ^ (1 << CAP_BRANS))) << 24)
#define CONST_A1 (((uint32_t) (1 ^ (1 << CAP_BRANS))) << 24)
#define CONST_M2 (((uint32_t) (2 ^ (1 << CAP_BRANS))) << 24)
#define CONST_M3 (((uint32_t) (3 ^ (1 << CAP_BRANS))) << 24)

// The macro STATE_WORD expands to the address of the i-th word of the state,
// which is always an x-word if i is even and a y-word otherwise.
#define STATE_WORD(s, i) (((i) & 1) ? (&((s)->y[(i)/2])) : (&((s)->x[(i)/2])))
