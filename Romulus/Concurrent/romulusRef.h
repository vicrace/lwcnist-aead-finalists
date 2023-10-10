#include "params.h"

// Skinny-128-384+ parameters: 128-bit block, 384-bit tweakey and 40 rounds
int BLOCK_SIZE = 128;
int TWEAKEY_SIZE = 384;
int N_RNDS = 40;

// 8-bit Sbox
const unsigned char sbox_8[256] = { 0x65 , 0x4c , 0x6a , 0x42 , 0x4b , 0x63 , 0x43 , 0x6b , 0x55 , 0x75 , 0x5a , 0x7a , 0x53 , 0x73 , 0x5b , 0x7b ,0x35 , 0x8c , 0x3a , 0x81 , 0x89 , 0x33 , 0x80 , 0x3b , 0x95 , 0x25 , 0x98 , 0x2a , 0x90 , 0x23 , 0x99 , 0x2b ,0xe5 , 0xcc , 0xe8 , 0xc1 , 0xc9 , 0xe0 , 0xc0 , 0xe9 , 0xd5 , 0xf5 , 0xd8 , 0xf8 , 0xd0 , 0xf0 , 0xd9 , 0xf9 ,0xa5 , 0x1c , 0xa8 , 0x12 , 0x1b , 0xa0 , 0x13 , 0xa9 , 0x05 , 0xb5 , 0x0a , 0xb8 , 0x03 , 0xb0 , 0x0b , 0xb9 ,0x32 , 0x88 , 0x3c , 0x85 , 0x8d , 0x34 , 0x84 , 0x3d , 0x91 , 0x22 , 0x9c , 0x2c , 0x94 , 0x24 , 0x9d , 0x2d ,0x62 , 0x4a , 0x6c , 0x45 , 0x4d , 0x64 , 0x44 , 0x6d , 0x52 , 0x72 , 0x5c , 0x7c , 0x54 , 0x74 , 0x5d , 0x7d ,0xa1 , 0x1a , 0xac , 0x15 , 0x1d , 0xa4 , 0x14 , 0xad , 0x02 , 0xb1 , 0x0c , 0xbc , 0x04 , 0xb4 , 0x0d , 0xbd ,0xe1 , 0xc8 , 0xec , 0xc5 , 0xcd , 0xe4 , 0xc4 , 0xed , 0xd1 , 0xf1 , 0xdc , 0xfc , 0xd4 , 0xf4 , 0xdd , 0xfd ,0x36 , 0x8e , 0x38 , 0x82 , 0x8b , 0x30 , 0x83 , 0x39 , 0x96 , 0x26 , 0x9a , 0x28 , 0x93 , 0x20 , 0x9b , 0x29 ,0x66 , 0x4e , 0x68 , 0x41 , 0x49 , 0x60 , 0x40 , 0x69 , 0x56 , 0x76 , 0x58 , 0x78 , 0x50 , 0x70 , 0x59 , 0x79 ,0xa6 , 0x1e , 0xaa , 0x11 , 0x19 , 0xa3 , 0x10 , 0xab , 0x06 , 0xb6 , 0x08 , 0xba , 0x00 , 0xb3 , 0x09 , 0xbb ,0xe6 , 0xce , 0xea , 0xc2 , 0xcb , 0xe3 , 0xc3 , 0xeb , 0xd6 , 0xf6 , 0xda , 0xfa , 0xd3 , 0xf3 , 0xdb , 0xfb ,0x31 , 0x8a , 0x3e , 0x86 , 0x8f , 0x37 , 0x87 , 0x3f , 0x92 , 0x21 , 0x9e , 0x2e , 0x97 , 0x27 , 0x9f , 0x2f ,0x61 , 0x48 , 0x6e , 0x46 , 0x4f , 0x67 , 0x47 , 0x6f , 0x51 , 0x71 , 0x5e , 0x7e , 0x57 , 0x77 , 0x5f , 0x7f ,0xa2 , 0x18 , 0xae , 0x16 , 0x1f , 0xa7 , 0x17 , 0xaf , 0x01 , 0xb2 , 0x0e , 0xbe , 0x07 , 0xb7 , 0x0f , 0xbf ,0xe2 , 0xca , 0xee , 0xc6 , 0xcf ,0xe7 , 0xc7 , 0xef , 0xd2 , 0xf2 , 0xde , 0xfe , 0xd7 , 0xf7 , 0xdf , 0xff };

// ShiftAndSwitchRows permutation
const unsigned char P[16] = { 0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12 };

// Tweakey permutation
const unsigned char TWEAKEY_P[16] = { 9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7 };

// round constants
const unsigned char RC[40] = {
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A };

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
void AddKey(unsigned char state[4][4], unsigned char keyCells[3][4][4])
{
    int i, j, k;
    unsigned char pos;
    unsigned char keyCells_tmp[3][4][4];

    // apply the subtweakey to the internal state
    for (i = 0; i <= 1; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] ^= keyCells[0][i][j] ^ keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }

    // update the subtweakey states with the permutation
    for (k = 0; k < (int)(TWEAKEY_SIZE / BLOCK_SIZE); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                //application of the TWEAKEY permutation
                pos = TWEAKEY_P[j + 4 * i];
                keyCells_tmp[k][i][j] = keyCells[k][pos >> 2][pos & 0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for (k = 0; k < (int)(TWEAKEY_SIZE / BLOCK_SIZE); k++) {
        for (i = 0; i <= 1; i++) {
            for (j = 0; j < 4; j++) {
                //application of LFSRs for TK updates
                if (k == 1)
                {
                    keyCells_tmp[k][i][j] = ((keyCells_tmp[k][i][j] << 1) & 0xFE) ^ ((keyCells_tmp[k][i][j] >> 7) & 0x01) ^ ((keyCells_tmp[k][i][j] >> 5) & 0x01);
                }
                else if (k == 2)
                {
                    keyCells_tmp[k][i][j] = ((keyCells_tmp[k][i][j] >> 1) & 0x7F) ^ ((keyCells_tmp[k][i][j] << 7) & 0x80) ^ ((keyCells_tmp[k][i][j] << 1) & 0x80);
                }
            }
        }
    }

    for (k = 0; k < (int)(TWEAKEY_SIZE / BLOCK_SIZE); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                keyCells[k][i][j] = keyCells_tmp[k][i][j];
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void AddConstants(unsigned char state[4][4], int r)
{
    state[0][0] ^= (RC[r] & 0xf);
    state[1][0] ^= ((RC[r] >> 4) & 0x3);
    state[2][0] ^= 0x2;
}

// apply the 8-bit Sbox
void SubCell8(unsigned char state[4][4])
{
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = sbox_8[state[i][j]];
        }
    }
}

// Apply the ShiftRows function
void ShiftRows(unsigned char state[4][4])
{
    unsigned char tmp;
    tmp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;

    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;

    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}

void MixColumn(unsigned char state[4][4])
{
    int j;
    unsigned char temp;

    for (j = 0; j < 4; j++) {
        state[1][j] ^= state[2][j];
        state[2][j] ^= state[0][j];
        state[3][j] ^= state[2][j];

        temp = state[3][j];
        state[3][j] = state[2][j];
        state[2][j] = state[1][j];
        state[1][j] = state[0][j];
        state[0][j] = temp;
    }
}

// encryption function of Skinny-128-384+
void enc(unsigned char* input, const unsigned char* userkey)
{
    unsigned char state[4][4];
    unsigned char keyCells[3][4][4];
    int i;

    //memset(keyCells, 0, 48);	
    for (i = 0; i < 16; i++) {
        state[i >> 2][i & 0x3] = input[i] & 0xFF;
        keyCells[0][i >> 2][i & 0x3] = userkey[i] & 0xFF;
        keyCells[1][i >> 2][i & 0x3] = userkey[i + 16] & 0xFF;
        keyCells[2][i >> 2][i & 0x3] = userkey[i + 32] & 0xFF;
    }

    for (i = 0; i < N_RNDS; i++) {
        SubCell8(state);
        AddConstants(state, i);
        AddKey(state, keyCells);
        ShiftRows(state);
        MixColumn(state);

    }  //The last subtweakey should not be added

    for (i = 0; i < 16; i++)
        input[i] = state[i >> 2][i & 0x3] & 0xFF;
}

void skinny_128_384_plus_enc(unsigned char* input, const unsigned char* userkey) {
    enc(input, userkey);
}

///////////// Romulus M encryption /////////////

// Padding function: pads the byte length of the message mod 16 to the last incomplete block.
// For complete blocks it returns the same block.
void pad(const unsigned char* m, unsigned char* mp, int l, int len8) {
    int i;

    for (i = 0; i < l; i++) {
        if (i < len8) {
            mp[i] = m[i];
        }
        else if (i == l - 1) {
            mp[i] = (len8 & 0x0f);
        }
        else {
            mp[i] = 0x00;
        }
    }

}

// G(S): generates the key stream from the internal state by multiplying the state S by the constant matrix G
void g8A(unsigned char* s, unsigned char* c) {
    int i;

    for (i = 0; i < 16; i++) {
        c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
    }

}

// Rho(S,A) pads an A block and XORs it to the internal state.
void rho_ad(const unsigned char* m,
    unsigned char* s,
    int len8,
    int ver) {
    int i;
    unsigned char mp[16];


    pad(m, mp, ver, len8);
    for (i = 0; i < ver; i++) {
        s[i] = s[i] ^ mp[i];
    }

}

// Rho(S,M): pads an M block and outputs S'= M xor S and C = M xor G(S) 
void rho(const unsigned char* m,
    unsigned char* c,
    unsigned char* s,
    int len8,
    int ver) {
    int i;
    unsigned char mp[16];

    pad(m, mp, ver, len8);

    g8A(s, c);
    for (i = 0; i < ver; i++) {
        s[i] = s[i] ^ mp[i];
        if (i < len8) {
            c[i] = c[i] ^ mp[i];
        }
        else {
            c[i] = 0;
        }
    }

}

// Inverse-Rho(S,M): pads a C block and outputs S'= C xor G(S) xor S and M = C xor G(S) 
void irho(unsigned char* m,
    const unsigned char* c,
    unsigned char* s,
    int len8,
    int ver) {
    int i;
    unsigned char cp[16];

    pad(c, cp, ver, len8);

    g8A(s, m);
    for (i = 0; i < ver; i++) {
        if (i < len8) {
            s[i] = s[i] ^ cp[i] ^ m[i];
        }
        else {
            s[i] = s[i] ^ cp[i];
        }
        if (i < len8) {
            m[i] = m[i] ^ cp[i];
        }
        else {
            m[i] = 0;
        }
    }

}

// Resets the value of the counter.
void reset_lfsr_gf56(unsigned char* CNT) {
    CNT[0] = 0x01;
    CNT[1] = 0x00;
    CNT[2] = 0x00;
    CNT[3] = 0x00;
    CNT[4] = 0x00;
    CNT[5] = 0x00;
    CNT[6] = 0x00;
}

// Applies CNT'=2 * CNT (mod GF(2^56)), where GF(2^56) is defined using the irreducible polynomial
// x^56 + x^7 + x^4 + x^2 + 1
void lfsr_gf56(unsigned char* CNT) {
    unsigned char fb0;

    fb0 = CNT[6] >> 7;

    CNT[6] = (CNT[6] << 1) | (CNT[5] >> 7);
    CNT[5] = (CNT[5] << 1) | (CNT[4] >> 7);
    CNT[4] = (CNT[4] << 1) | (CNT[3] >> 7);
    CNT[3] = (CNT[3] << 1) | (CNT[2] >> 7);
    CNT[2] = (CNT[2] << 1) | (CNT[1] >> 7);
    CNT[1] = (CNT[1] << 1) | (CNT[0] >> 7);
    if (fb0 == 1) {
        CNT[0] = (CNT[0] << 1) ^ 0x95;
    }
    else {
        CNT[0] = (CNT[0] << 1);
    }
}

//different from T
// Combines the secret key, nonce (or A block), counter and domain bits to form the full 384-bit tweakey
void compose_tweakey(unsigned char* KT,
    const unsigned char* K,
    unsigned char* T,
    unsigned char* CNT,
    unsigned char D,
    int t) {

    int i;

    for (i = 0; i < 7; i++) {
        KT[i] = CNT[i];
    }
    KT[i] = D;
    for (i = 8; i < 16; i++) {
        KT[i] = 0x00;
    }
    for (i = 0; i < t; i++) {
        KT[i + 16] = T[i];
    }
    for (i = 0; i < 16; i++) {
        KT[i + 16 + t] = K[i];
    }

}

//different from T
// An interface between Romulus and the underlying TBC
void block_cipher(unsigned char* s,
    const unsigned char* k, unsigned char* T,
    unsigned char* CNT, unsigned char D, int t) {
    unsigned char KT[48];

    compose_tweakey(KT, k, T, CNT, D, t);
    skinny_128_384_plus_enc(s, KT);

}

// Calls the TBC using the nonce as part of the tweakey
void nonce_encryption(const unsigned char* N,
    unsigned char* CNT,
    unsigned char* s, const unsigned char* k,
    int t, unsigned char D) {
    unsigned char T[16];
    int i;
    for (i = 0; i < t; i++) {
        T[i] = N[i];
    }
    block_cipher(s, k, T, CNT, D, t);

}

// Generates the tag T from the final state S by applying T=G(S).
void generate_tag(unsigned char** c, unsigned char* s,
    int n, unsigned long long* clen) {

    g8A(s, *c);
    *c = *c + n;
    *c = *c - *clen;

}

// Absorbs and encrypts the message blocks.
unsigned long long msg_encryption(const unsigned char** M, unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char* s, const unsigned char* k,
    unsigned int n, unsigned int t, unsigned char D,
    unsigned long long mlen) {
    int len8;


    if (mlen >= n) {
        len8 = n;
        mlen = mlen - n;
    }
    else {
        len8 = mlen;
        mlen = 0;
    }
    rho(*M, *c, s, len8, n);
    *c = *c + len8;
    *M = *M + len8;
    lfsr_gf56(CNT);
    nonce_encryption(N, CNT, s, k, t, D);
    return mlen;
}

// Absorbs and decrypts the ciphertext blocks.
unsigned long long msg_decryption(unsigned char** M, const unsigned char** c,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char* s, const unsigned char* k,
    unsigned int n, unsigned int t, unsigned char D,
    unsigned long long clen) {
    int len8;

    if (clen >= n) {
        len8 = n;
        clen = clen - n;
    }
    else {
        len8 = clen;
        clen = 0;
    }
    irho(*M, *c, s, len8, n);
    *c = *c + len8;
    *M = *M + len8;
    lfsr_gf56(CNT);
    nonce_encryption(N, CNT, s, k, t, D);
    return clen;
}

// Handles the special case when the number of blocks of A is odd
unsigned long long ad2msg_encryption(const unsigned char** M,
    unsigned char* CNT,
    unsigned char* s, const unsigned char* k,
    unsigned int t, unsigned char D,
    unsigned long long mlen) {
    unsigned char T[16];
    int len8;

    if (mlen <= t) {
        len8 = mlen;
        mlen = 0;
    }
    else {
        len8 = t;
        mlen = mlen - t;
    }

    pad(*M, T, t, len8);

    block_cipher(s, k, T, CNT, D, t);
    lfsr_gf56(CNT);
    *M = *M + len8;

    return mlen;

}

// Absorbs the AD blocks.
unsigned long long ad_encryption(const unsigned char** A, unsigned char* s,
    const unsigned char* k, unsigned long long adlen,
    unsigned char* CNT,
    unsigned char D,
    unsigned int n, unsigned int t) {

    unsigned char T[16];
    int len8;

    if (adlen >= n) {
        len8 = n;
        adlen = adlen - n;
    }
    else {
        len8 = adlen;
        adlen = 0;
    }
    rho_ad(*A, s, len8, n);
    *A = *A + len8;
    lfsr_gf56(CNT);

    if (adlen != 0) {
        if (adlen >= t) {
            len8 = t;
            adlen = adlen - t;
        }
        else {
            len8 = adlen;
            adlen = 0;
        }
        pad(*A, T, t, len8);
        *A = *A + len8;
        block_cipher(s, k, T, CNT, D, t);
        lfsr_gf56(CNT);
    }

    return adlen;
}



///////////// Romulus T ///////////////////
// Initialization function: KDF
void kdf(const unsigned char* K, unsigned char* Z, const unsigned char* N, unsigned char* CNT) {

    int i;
    unsigned char T[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    for (i = 0; i < 16; i++) {
        Z[i] = N[i];
    }

    block_cipher(Z, K, T, CNT, 66,16);
}


// Encrypts the message blocks.
unsigned long long msg_encryptionT(const unsigned char** M, unsigned char** C,
    const unsigned char* N,
    unsigned char* CNT,
    unsigned char* Z,
    unsigned long long mlen) {

    unsigned char S[16];
    unsigned char T[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    int len8, i;

    if (mlen >= 16) {
        len8 = 16;
        mlen = mlen - 16;
    }
    else {
        len8 = mlen;
        mlen = 0;
    }

    for (i = 0; i < 16; i++) {
        S[i] = N[i];
    }

    block_cipher(S, Z, T, CNT, 64, 16);

    for (i = 0; i < len8; i++) {
        (*C)[i] = (*M)[i] ^ S[i];
    }
    *C = *C + len8;
    *M = *M + len8;

    for (i = 0; i < 16; i++) {
        S[i] = N[i];
    }

    if (mlen != 0) {
        block_cipher(S, Z, T, CNT, 65, 16);

        for (i = 0; i < 16; i++) {
            Z[i] = S[i];
        }
    }


    lfsr_gf56(CNT);

    return mlen;

}

// Generates the tag T from the final state S by applying the Tag Generation Function (TGF).
void generate_tagT(unsigned char* T, unsigned char* L,
    unsigned char* CNT, const unsigned char* K) {

    int i;
    block_cipher(L, K, L + 16, CNT, 68, 16);

    for (i = 0; i < 16; i++) {
        T[i] = L[i];
    }

}

/////// Hash function  ///////////
// The hirose double - block length(DBL) compression function.
void hirose_128_128_256(unsigned char* h,
    unsigned char* g,
    const unsigned char* m) {
    unsigned char key[48];
    unsigned char hh[16];
    int i;

    for (i = 0; i < 16; i++) { // assign the key for the
                               // hirose compresison function
        key[i] = g[i];
        g[i] = h[i];
        hh[i] = h[i];
    }
    g[0] ^= 0x01;
    for (i = 0; i < 32; i++) {
        key[i + 16] = m[i];
    }

    skinny_128_384_plus_enc(h, key);
    skinny_128_384_plus_enc(g, key);

    for (i = 0; i < 16; i++) {
        h[i] ^= hh[i];
        g[i] ^= hh[i];
    }
    g[0] ^= 0x01;

}

// Sets the initial value to 0^2n
void initialize(unsigned char* h,
    unsigned char* g) {
    unsigned char i;

    for (i = 0; i < 16; i++) {
        h[i] = 0;
        g[i] = 0;
    }
}

// Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N 
void ipad_256(const unsigned char* m, unsigned char* mp, int l, int len8) {
    int i;

    for (i = 0; i < l; i++) {
        if (i < len8) {
            mp[i] = m[i];
        }
        else if (i == l - 1) {
            mp[i] = (len8 & 0x1f);
        }
        else {
            mp[i] = 0x00;
        }
    }

}

// Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N 
void ipad_128(const unsigned char* m, unsigned char* mp, int l, int len8) {
    int i;

    for (i = 0; i < l; i++) {
        if (i < len8) {
            mp[i] = m[i];
        }
        else if (i == l - 1) {
            mp[i] = (len8 & 0xf);
        }
        else {
            mp[i] = 0x00;
        }
    }

}

int crypto_hash(
    unsigned char* out,
    const unsigned char* in,
    unsigned long long inlen
)
{
    unsigned char h[16];
    unsigned char g[16];
    unsigned long long mlen;
    unsigned char p[32];
    unsigned char i;

    mlen = inlen;

    initialize(h, g);
    while (mlen >= 32) { // Normal loop
        hirose_128_128_256(h, g, in);
        in += 32;
        mlen -= 32;
    }
    // Partial block (or in case there is no partial block we add a 0^2n block
    ipad_256(in, p, 32, mlen);
    h[0] ^= 2;
    hirose_128_128_256(h, g, p);

    for (i = 0; i < 16; i++) { // Assign the output tag
        out[i] = h[i];
        out[i + 16] = g[i];
    }

    return 0;
}

// This function is required for Romulus-T. It assumes that the input comes in three parts that can
// be stored in different locations in the memory. It processes these inputs sequentially.
// The padding is ipad_256(ipad*_128(A)||ipad*_128(C)||N|| CNT )
// A and C are of variable length, while N is of 16 bytes and CNT is of 7 bytes

int crypto_hash_vector(
    unsigned char* out,
    const unsigned char* A,
    unsigned long long adlen,
    const unsigned char* C,
    unsigned long long clen,
    const unsigned char* N,
    unsigned char* CNT
)
{
    unsigned char h[16];
    unsigned char g[16];
    unsigned char p[32];
    unsigned char i, n, adempty, cempty;

    n = 16;

    if (adlen == 0) {
        adempty = 1;
    }
    else {
        adempty = 0;
    }

    if (clen == 0) {
        cempty = 1;
    }
    else {
        cempty = 0;
    }

    reset_lfsr_gf56(CNT);

    initialize(h, g);
    while (adlen >= 32) { // AD Normal loop
        hirose_128_128_256(h, g, A);
        A += 32;
        adlen -= 32;
    }
    // Partial block (or in case there is no partial block we add a 0^2n block
    if (adlen >= 16) {
        ipad_128(A, p, 32, adlen);
        hirose_128_128_256(h, g, p);
    }
    else if ((adlen >= 0) && (adempty == 0)) {
        ipad_128(A, p, 16, adlen);
        adlen = 0;
        if (clen >= 16) {
            for (i = 0; i < 16; i++) {
                p[i + 16] = C[i];
            }
            hirose_128_128_256(h, g, p);
            lfsr_gf56(CNT);
            clen -= 16;
            C += 16;
        }
        else if (clen > 0) {
            ipad_128(C, p + 16, 16, clen);
            hirose_128_128_256(h, g, p);
            clen = 0;
            cempty = 1;
            C += 16;
            lfsr_gf56(CNT);
        }
        else {
            for (i = 0; i < 16; i++) { // Pad the nonce
                p[i + 16] = N[i];
            }
            hirose_128_128_256(h, g, p);
            n = 0;
        }
    }

    while (clen >= 32) { // C Normal loop
        hirose_128_128_256(h, g, C);
        C += 32;
        clen -= 32;
        lfsr_gf56(CNT);
        lfsr_gf56(CNT);
    }
    if (clen > 16) {
        ipad_128(C, p, 32, clen);
        hirose_128_128_256(h, g, p);
        lfsr_gf56(CNT);
        lfsr_gf56(CNT);
    }
    else if (clen == 16) {
        ipad_128(C, p, 32, clen);
        hirose_128_128_256(h, g, p);
        lfsr_gf56(CNT);
    }
    else if ((clen >= 0) && (cempty == 0)) {
        ipad_128(C, p, 16, clen);
        if (clen > 0) {
            lfsr_gf56(CNT);
        }
        for (i = 0; i < 16; i++) { // Pad the nonce
            p[i + 16] = N[i];
        }
        hirose_128_128_256(h, g, p);
        n = 0;
    }

    if (n == 16) {
        for (i = 0; i < 16; i++) { // Pad the nonce and counter
            p[i] = N[i];
        }
        for (i = 16; i < 23; i++) {
            p[i] = CNT[i - 16];
        }
        ipad_256(p, p, 32, 23);
    }
    else {
        ipad_256(CNT, p, 32, 7);
    }
    h[0] ^= 2;
    hirose_128_128_256(h, g, p);

    for (i = 0; i < 16; i++) { // Assign the output tag
        out[i] = h[i];
        out[i + 16] = g[i];
    }

    return 0;

}

