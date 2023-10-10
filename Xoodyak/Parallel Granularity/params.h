#ifndef PARAMS_H
#define PARAMS_H

// GPU
#define CRYPTO_KEYBYTES     16
#define CRYPTO_NSECBYTES    0
#define CRYPTO_NPUBBYTES    16
#define CRYPTO_ABYTES       16
#define CRYPTO_NOOVERLAP    1

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32
#define ALEN MAX_ASSOCIATED_DATA_LENGTH
#define MLEN MAX_MESSAGE_LENGTH
#define MAX_CIPHER_LENGTH (MLEN + CRYPTO_ABYTES)
#define OFFSET(arr,i,offset) (arr + (i*offset))			
//#define PRINT
//#define PRINTC
#define BATCH_SIZE	5
#define fineLevel 4		// Change to 2 / 4 
#define Tlimit 1025
#define PERMUTATION_ROUND 12
//#define WRITEFILE


//XOODOO PARAM
#define Xoodoo_implementation      "32-bit reference implementation"
#define Xoodoo_stateSizeInBytes    (3*4*4)
#define Xoodoo_stateAlignment      4
#define Xoodoo_HasNround

#define MAXROUNDS   12
#define NROWS       3
#define NCOLUMS     4
#define NLANES      (NCOLUMS*NROWS)
#define Dump(text, a, level)
#define MyMin(a,b)  (((a) < (b)) ? (a) : (b))

/*    Round constants    */
#define _rc12   0x00000058
#define _rc11   0x00000038
#define _rc10   0x000003C0
#define _rc9    0x000000D0
#define _rc8    0x00000120
#define _rc7    0x00000014
#define _rc6    0x00000060
#define _rc5    0x0000002C
#define _rc4    0x00000380
#define _rc3    0x000000F0
#define _rc2    0x000001A0
#define _rc1    0x00000012

typedef struct {
	uint8_t         state[Xoodoo_stateSizeInBytes];
	unsigned int    phase;
	unsigned int    mode;
	unsigned int    Rabsorb;
	unsigned int    Rsqueeze;
} Xoodyak_Instance;


#if !defined(ROTL32)
#if defined (__arm__) && !defined(__GNUC__)
#define ROTL32(a, offset)                       __ror(a, (32-(offset))%32)
#elif defined(_MSC_VER)
#define ROTL32(a, offset)                       _rotl(a, (offset)%32)
#else
#define ROTL32(a, offset)                       ((((uint32_t)a) << ((offset)%32)) ^ (((uint32_t)a) >> ((32-(offset))%32)))
#endif
#endif

#if !defined(READ32_UNALIGNED)
#if defined (__arm__) && !defined(__GNUC__)
#define READ32_UNALIGNED(argAddress)            (*((const __packed uint32_t*)(argAddress)))
#elif defined(_MSC_VER)
#define READ32_UNALIGNED(argAddress)            (*((const uint32_t*)(argAddress)))
#else
#define READ32_UNALIGNED(argAddress)            (*((const uint32_t*)(argAddress)))
#endif
#endif

#if !defined(WRITE32_UNALIGNED)
#if defined (__arm__) && !defined(__GNUC__)
#define WRITE32_UNALIGNED(argAddress, argData)  (*((__packed uint32_t*)(argAddress)) = (argData))
#elif defined(_MSC_VER)
#define WRITE32_UNALIGNED(argAddress, argData)  (*((uint32_t*)(argAddress)) = (argData))
#else
#define WRITE32_UNALIGNED(argAddress, argData)  (*((uint32_t*)(argAddress)) = (argData))
#endif
#endif

#if !defined(index)
#define    index(__x,__y)    ((((__y) % NROWS) * NCOLUMS) + ((__x) % NCOLUMS))
#endif

typedef    uint32_t tXoodooLane;


//XOODYAK PARAM

#define Cyclist_ModeHash    1
#define Cyclist_ModeKeyed   2

#define Cyclist_PhaseDown   1
#define Cyclist_PhaseUp     2

#define Cyclist_Rhash                   16
#define Cyclist_Rkin                    44
#define Cyclist_Rkout                   24
#define Cyclist_lRatchet                16

#endif