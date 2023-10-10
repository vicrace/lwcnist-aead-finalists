#include "params.h"
#include <stddef.h> 
#include <string.h> 

///////////////////////////////////////////////////////////////////////////////
/////////////                   UnOp CPU                          /////////////
///////////////////////////////////////////////////////////////////////////////

typedef unsigned __int8 uint8_t;
typedef unsigned __int32 uint32_t;

#define MAX_BRANCHES 8

typedef struct {
    uint32_t x[MAX_BRANCHES];
    uint32_t y[MAX_BRANCHES];
} SparkleState;

// Round constants
static const uint32_t RCON[MAX_BRANCHES] = { \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, \
  0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D  \
};

void linear_layer(SparkleState* state, int brans)
{
    int i, b = brans / 2;
    uint32_t* x = state->x, * y = state->y;
    uint32_t tmp;

    // Feistel function (adding to y part)
    tmp = 0;
    for (i = 0; i < b; i++)
        tmp ^= x[i];
    tmp = ELL(tmp);
    for (i = 0; i < b; i++)
        y[i + b] ^= (tmp ^ y[i]);

    // Feistel function (adding to x part)
    tmp = 0;
    for (i = 0; i < b; i++)
        tmp ^= y[i];
    tmp = ELL(tmp);
    for (i = 0; i < b; i++)
        x[i + b] ^= (tmp ^ x[i]);

    // Branch swap with 1-branch left-rotation of right side
    // <------- left side --------> <------- right side ------->
    //    0    1    2 ...  B-2  B-1    B  B+1  B+2 ... 2B-2 2B-1
    //  B+1  B+2  B+3 ... 2B-1    B    0    1    2 ...  B-2  B-1

    // Branch swap of the x part
    tmp = x[0];
    for (i = 0; i < b - 1; i++) {
        x[i] = x[i + b + 1];
        x[i + b + 1] = x[i + 1];
    }
    x[b - 1] = x[b];
    x[b] = tmp;

    // Branch swap of the y part
    tmp = y[0];
    for (i = 0; i < b - 1; i++) {
        y[i] = y[i + b + 1];
        y[i + b + 1] = y[i + 1];
    }
    y[b - 1] = y[b];
    y[b] = tmp;
}

void sparkle_ref(SparkleState* state, int brans, int steps)
{
    int i, j;  // Step and branch counter

    // The number of branches must be even and not bigger than MAX_BRANCHES.
    //assert(((brans & 1) == 0) && (brans >= 4) && (brans <= MAX_BRANCHES));

    for (i = 0; i < steps; i++) {
        // Add step counter
        state->y[0] ^= RCON[i % MAX_BRANCHES];
        state->y[1] ^= i;
        // ARXBox layer
        for (j = 0; j < brans; j++)
            ARXBOX(state->x[j], state->y[j], RCON[j]);
        // Linear layer
        linear_layer(state, brans);
    }
}

/////////////                  Encrypt                            /////////////

// Rho and rate-whitening for the authentication of associated data.

static void rho_whi_aut(SparkleState* state, const uint8_t* in, size_t inlen)
{
    uint32_t inbuf[RATE_WORDS] = { 0 };
    uint32_t* left_word, * right_word, tmp;  // Feistel-swap
    int i;

    memcpy(inbuf, in, inlen);
    if (inlen < RATE_BYTES)  // padding (only for last block)
        *(((uint8_t*)inbuf) + inlen) = 0x80;

    // Rho1 part1: Feistel swap of the rate-part of the state
    for (i = 0; i < RATE_BRANS; i++) {
        left_word = STATE_WORD(state, i);
        right_word = STATE_WORD(state, (RATE_BRANS + i));
        tmp = *left_word;
        *left_word = *right_word;
        *right_word ^= tmp;
    }
    // Rho1 part2: rate-part of state is XORed with assoc data
    for (i = 0; i < RATE_BRANS; i++) {
        state->x[i] ^= inbuf[2 * i];
        state->y[i] ^= inbuf[2 * i + 1];
    }
    // Rate-whitening: capacity-part is XORed to the rate-part
    for (i = 0; i < RATE_BRANS; i++) {
        state->x[i] ^= state->x[RATE_BRANS + (i % CAP_BRANS)];
        state->y[i] ^= state->y[RATE_BRANS + (i % CAP_BRANS)];
    }
}


// Rho and rate-whitening for the encryption of plaintext.

static void rho_whi_enc(SparkleState* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    uint32_t inbuf[RATE_WORDS] = { 0 }, outbuf[RATE_WORDS];
    uint32_t* left_word, * right_word, tmp;  // Feistel-swap
    int i;

    memcpy(inbuf, in, inlen);
    if (inlen < RATE_BYTES)  // padding (only for last block)
        *(((uint8_t*)inbuf) + inlen) = 0x80;

    // Rho2: ciphertext = plaintext XOR rate-part of the state
    for (i = 0; i < RATE_BRANS; i++) {
        outbuf[2 * i] = inbuf[2 * i] ^ state->x[i];
        outbuf[2 * i + 1] = inbuf[2 * i + 1] ^ state->y[i];
    }
    // Rho1 part1: Feistel swap of the rate-part of the state
    for (i = 0; i < RATE_BRANS; i++) {
        left_word = STATE_WORD(state, i);
        right_word = STATE_WORD(state, (RATE_BRANS + i));
        tmp = *left_word;
        *left_word = *right_word;
        *right_word ^= tmp;
    }
    // Rho1 part2: rate-part of state is XORed with ciphertext
    for (i = 0; i < RATE_BRANS; i++) {
        state->x[i] ^= inbuf[2 * i];
        state->y[i] ^= inbuf[2 * i + 1];
    }
    // Rate-whitening: capacity-part is XORed to the rate-part
    for (i = 0; i < RATE_BRANS; i++) {
        state->x[i] ^= state->x[RATE_BRANS + (i % CAP_BRANS)];
        state->y[i] ^= state->y[RATE_BRANS + (i % CAP_BRANS)];
    }
    memcpy(out, outbuf, inlen);
}


// Rho and rate-whitening for the decryption of ciphertext.

static void rho_whi_dec(SparkleState* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    uint32_t inbuf[RATE_WORDS] = { 0 }, outbuf[RATE_WORDS];
    SparkleState statebuf;
    uint32_t* left_word, * right_word, tmp;  // Feistel-swap
    int i;

    memcpy(inbuf, in, inlen);
    memcpy(&statebuf, state, sizeof(SparkleState));
    if (inlen < RATE_BYTES)  // padding (only for last block!)
        *(((uint8_t*)inbuf) + inlen) = 0x80;

    // Rho2': plaintext = ciphertext XOR rate-part of the state
    for (i = 0; i < RATE_BRANS; i++) {
        outbuf[2 * i] = inbuf[2 * i] ^ state->x[i];
        outbuf[2 * i + 1] = inbuf[2 * i + 1] ^ state->y[i];
    }
    // Rho1' part1: Feistel swap of the rate-part of the state
    for (i = 0; i < RATE_BRANS; i++) {
        left_word = STATE_WORD(state, i);
        right_word = STATE_WORD(state, (RATE_BRANS + i));
        tmp = *left_word;
        *left_word = *right_word;
        *right_word ^= tmp;
    }
    if (inlen < RATE_BYTES) {
        // padding of last block of plaintext (computed by Rho2')
        memset((((uint8_t*)outbuf) + inlen), 0, (RATE_BYTES - inlen));
        *(((uint8_t*)outbuf) + inlen) = 0x80;
        // Rho1 part2: rate-part of state is XORed with plaintext
        for (i = 0; i < RATE_BRANS; i++) {
            state->x[i] ^= outbuf[2 * i];
            state->y[i] ^= outbuf[2 * i + 1];
        }
    }
    else {
        // Rho1' part2: rate-part XORed with orig rate and ciphertext
        for (i = 0; i < RATE_BRANS; i++) {
            state->x[i] ^= statebuf.x[i] ^ inbuf[2 * i];
            state->y[i] ^= statebuf.y[i] ^ inbuf[2 * i + 1];
        }
    }
    // Rate-whitening: capacity-part is XORed to the rate-part
    for (i = 0; i < RATE_BRANS; i++) {
        state->x[i] ^= state->x[RATE_BRANS + (i % CAP_BRANS)];
        state->y[i] ^= state->y[RATE_BRANS + (i % CAP_BRANS)];
    }
    memcpy(out, outbuf, inlen);
}

/////////////                   Functions                          /////////////

// The Initialize function loads nonce and key into the state and executes the
// SPARKLE permutation with the big number of steps.

void Initialize(SparkleState* state, const uint8_t* key, const uint8_t* nonce)
{
    uint32_t keybuf[KEY_WORDS], noncebuf[NONCE_WORDS];
    int i;

    // to prevent (potentially) unaligned memory accesses
    memcpy(keybuf, key, KEY_BYTES);
    memcpy(noncebuf, nonce, NONCE_BYTES);
    // load nonce into the rate-part of the state
    for (i = 0; i < NONCE_WORDS / 2; i++) {
        state->x[i] = noncebuf[2 * i];
        state->y[i] = noncebuf[2 * i + 1];
    }
    // load key into the capacity-part of the sate
    for (i = 0; i < KEY_WORDS / 2; i++) {
        state->x[RATE_BRANS + i] = keybuf[2 * i];
        state->y[RATE_BRANS + i] = keybuf[2 * i + 1];
    }
    // execute SPARKLE with big number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The ProcessAssocData function absorbs the associated data, which becomes
// only authenticated but not encrypted, into the state (in blocks of size
// RATE_BYTES). Note that this function MUST NOT be called when the length of
// the associated data is 0.

void ProcessAssocData(SparkleState* state, const uint8_t* in, size_t inlen)
{
    // Main Authentication Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_aut(state, in, RATE_BYTES);
        // execute SPARKLE with slim number of steps
        sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        in += RATE_BYTES;
    }

    // Authentication of Last Block

    // addition of constant A0 or A1 to the state
    state->y[STATE_BRANS - 1] ^= ((inlen < RATE_BYTES) ? CONST_A0 : CONST_A1);
    // combined Rho and rate-whitening operation
    rho_whi_aut(state, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The ProcessPlainText function encrypts the plaintext (in blocks of size
// RATE_BYTES) and generates the respective ciphertext. The uint8_t-array 'in'
// contains the plaintext and the ciphertext is written to uint8_t-array 'out'
// ('in' and 'out' can be the same array, i.e. they can have the same start
// address). Note that this function MUST NOT be called when the length of the
// plaintext is 0.

void ProcessPlainText(SparkleState* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    // Main Encryption Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_enc(state, out, in, RATE_BYTES);
        // execute SPARKLE with slim number of steps
        sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        out += RATE_BYTES;
        in += RATE_BYTES;
    }

    // Encryption of Last Block

    // addition of constant M2 or M3 to the state
    state->y[STATE_BRANS - 1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
    // combined Rho and rate-whitening (incl. padding)
    rho_whi_enc(state, out, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}


// The Finalize function adds the key to the capacity part of the state.

void Finalize(SparkleState* state, const uint8_t* key)
{
    uint32_t keybuf[KEY_WORDS];
    int i;

    // to prevent (potentially) unaligned memory accesses
    memcpy(keybuf, key, KEY_BYTES);
    // add key to the capacity-part of the state
    for (i = 0; i < KEY_WORDS / 2; i++) {
        state->x[RATE_BRANS + i] ^= keybuf[2 * i];
        state->y[RATE_BRANS + i] ^= keybuf[2 * i + 1];
    }
}


// The GenerateTag function generates an authentication tag.

void GenerateTag(SparkleState* state, uint8_t* tag)
{
    uint32_t tagbuf[TAG_WORDS];
    int i;

    for (i = 0; i < TAG_WORDS / 2; i++) {
        tagbuf[2 * i] = state->x[RATE_BRANS + i];
        tagbuf[2 * i + 1] = state->y[RATE_BRANS + i];
    }
    memcpy(tag, tagbuf, TAG_BYTES);
}


// The ProcessCipherText function decrypts the ciphertext (in blocks of size
// RATE_BYTES) and generates the respective plaintext. The uint8_t-array 'in'
// contains the ciphertext and the plaintext is written to uint8_t-array 'out'
// ('in' and 'out' can be the same array, i.e. they can have the same start
// address). Note that this function MUST NOT be called when the length of the
// ciphertext is 0.

void ProcessCipherText(SparkleState* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    // Main Decryption Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_dec(state, out, in, RATE_BYTES);
        // execute SPARKLE with slim number of steps
        sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        out += RATE_BYTES;
        in += RATE_BYTES;
    }

    // Decryption of Last Block

    // addition of constant M2 or M3 to the state
    state->y[STATE_BRANS - 1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
    // combined Rho and rate-whitening (incl. padding)
    rho_whi_dec(state, out, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_ref(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}





///////////////////////////////////////////////////////////////////////////////
/////////////                    Op CPU                           /////////////
///////////////////////////////////////////////////////////////////////////////

#define MIN_SIZE(a, b) ((sizeof(a) < sizeof(b)) ? sizeof(a) : sizeof(b))
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__ICL)
#define UI32_ALIGN_BYTES MIN_SIZE(unsigned __int32, size_t)
#else
#include <stdint.h>
#define UI32_ALIGN_BYTES MIN_SIZE(uint32_t, uint_fast8_t)
#endif

#if (RATE_WORDS > CAP_WORDS)
#define CAP_INDEX(i) ((i) & (CAP_WORDS-1))
#else  // RATE_WORDS <= CAP_WORDS
#define CAP_INDEX(i) (i)
#endif

void sparkle_opt(uint32_t* state, int brans, int steps)
{
    int i, j;  // Step and branch counter
    uint32_t rc, tmpx, tmpy, x0, y0;

    for (i = 0; i < steps; i++) {
        // Add round constant
        state[1] ^= RCON[i % MAX_BRANCHES];
        state[3] ^= i;
        // ARXBOX layer
        for (j = 0; j < 2 * brans; j += 2) {
            rc = RCON[j >> 1];
            state[j] += ROT(state[j + 1], 31);
            state[j + 1] ^= ROT(state[j], 24);
            state[j] ^= rc;
            state[j] += ROT(state[j + 1], 17);
            state[j + 1] ^= ROT(state[j], 17);
            state[j] ^= rc;
            state[j] += state[j + 1];
            state[j + 1] ^= ROT(state[j], 31);
            state[j] ^= rc;
            state[j] += ROT(state[j + 1], 24);
            state[j + 1] ^= ROT(state[j], 16);
            state[j] ^= rc;
        }
        // Linear layer
        tmpx = x0 = state[0];
        tmpy = y0 = state[1];
        for (j = 2; j < brans; j += 2) {
            tmpx ^= state[j];
            tmpy ^= state[j + 1];
        }
        tmpx = ELL(tmpx);
        tmpy = ELL(tmpy);
        for (j = 2; j < brans; j += 2) {
            state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
            state[j + brans] = state[j];
            state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
            state[j + brans + 1] = state[j + 1];
        }
        state[brans - 2] = state[brans] ^ x0 ^ tmpy;
        state[brans] = x0;
        state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
        state[brans + 1] = y0;
    }
}


// Rho and rate-whitening for the authentication of associated data. The third
// parameter indicates whether the uint8_t-pointer 'in' is properly aligned to
// permit casting to a uint32_t-pointer. If this is the case then array 'in' is
// processed directly, otherwise it is first copied to an aligned buffer.

static void rho_whi_aut_Op(uint32_t* state, const uint8_t* in, int aligned)
{
    uint32_t buffer[RATE_WORDS];
    uint32_t* in32;
    uint32_t tmp;
    int i, j;

    if (aligned) {  // 'in' can be casted to uint32_t pointer
        in32 = (uint32_t*)in;
    }
    else {  // 'in' is not sufficiently aligned for casting
        memcpy(buffer, in, RATE_BYTES);
        in32 = (uint32_t*)&buffer;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp = state[i];
        state[i] = state[j] ^ in32[i] ^ state[RATE_WORDS + i];
        state[j] ^= tmp ^ in32[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
    }
}


// Rho and rate-whitening for the authentication of the last associated-data
// block. Since this last block may require padding, it is always copied to a
// buffer.

static void rho_whi_aut_last_Op(uint32_t* state, const uint8_t* in, size_t inlen)
{
    uint32_t buffer[RATE_WORDS];
    uint8_t* bufptr;
    uint32_t tmp;
    int i, j;

    memcpy(buffer, in, inlen);
    if (inlen < RATE_BYTES) {  // padding
        bufptr = ((uint8_t*)buffer) + inlen;
        memset(bufptr, 0, (RATE_BYTES - inlen));
        *bufptr = 0x80;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp = state[i];
        state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
        state[j] ^= tmp ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
    }
}


// Rho and rate-whitening for the encryption of plaintext. The third parameter
// indicates whether the uint8_t-pointers 'in' and 'out' are properly aligned
// to permit casting to uint32_t-pointers. If this is the case then array 'in'
// and 'out' are processed directly, otherwise 'in' is copied to an aligned
// buffer.

static void rho_whi_enc_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    int aligned)
{
    uint32_t buffer[RATE_WORDS];
    uint32_t* in32, * out32;
    uint32_t tmp1, tmp2;
    int i, j;

    if (aligned) {  // 'in' and 'out' can be casted to uint32_t pointer
        in32 = (uint32_t*)in;
        out32 = (uint32_t*)out;
    }
    else {  // 'in' or 'out' is not sufficiently aligned for casting
        memcpy(buffer, in, RATE_BYTES);
        in32 = out32 = (uint32_t*)buffer;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp1 = state[i];
        tmp2 = state[j];
        state[i] = state[j] ^ in32[i] ^ state[RATE_WORDS + i];
        state[j] ^= tmp1 ^ in32[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
        out32[i] = in32[i] ^ tmp1;
        out32[j] = in32[j] ^ tmp2;
    }

    if (!aligned)
        memcpy(out, buffer, RATE_BYTES);
}


// Rho and rate-whitening for the encryption of the last plaintext block. Since
// this last block may require padding, it is always copied to a buffer.

static void rho_whi_enc_last_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    uint32_t buffer[RATE_WORDS];
    uint32_t tmp1, tmp2;
    uint8_t* bufptr;
    int i, j;

    memcpy(buffer, in, inlen);
    if (inlen < RATE_BYTES) {  // padding
        bufptr = ((uint8_t*)buffer) + inlen;
        memset(bufptr, 0, (RATE_BYTES - inlen));
        *bufptr = 0x80;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp1 = state[i];
        tmp2 = state[j];
        state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
        state[j] ^= tmp1 ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
        buffer[i] ^= tmp1;
        buffer[j] ^= tmp2;
    }
    memcpy(out, buffer, inlen);
}


// Rho and rate-whitening for the decryption of ciphertext. The third parameter
// indicates whether the uint8_t-pointers 'in' and 'out' are properly aligned
// to permit casting to uint32_t-pointers. If this is the case then array 'in'
// and 'out' are processed directly, otherwise 'in' is copied to an aligned
// buffer.

static void rho_whi_dec_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    int aligned)
{
    uint32_t buffer[RATE_WORDS];
    uint32_t* in32, * out32;
    uint32_t tmp1, tmp2;
    int i, j;

    if (aligned) {  // 'in' and 'out' can be casted to uint32_t pointer
        in32 = (uint32_t*)in;
        out32 = (uint32_t*)out;
    }
    else {  // 'in' or 'out' is not sufficiently aligned for casting
        memcpy(buffer, in, RATE_BYTES);
        in32 = out32 = (uint32_t*)buffer;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp1 = state[i];
        tmp2 = state[j];
        state[i] ^= state[j] ^ in32[i] ^ state[RATE_WORDS + i];
        state[j] = tmp1 ^ in32[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
        out32[i] = in32[i] ^ tmp1;
        out32[j] = in32[j] ^ tmp2;
    }

    if (!aligned)
        memcpy(out, buffer, RATE_BYTES);
}


// Rho and rate-whitening for the decryption of the last ciphertext block.
// Since this last block may require padding, it is always copied to a buffer.

static void rho_whi_dec_last_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    uint32_t buffer[RATE_WORDS];
    uint32_t tmp1, tmp2;
    uint8_t* bufptr;
    int i, j;

    memcpy(buffer, in, inlen);
    if (inlen < RATE_BYTES) {  // padding
        bufptr = ((uint8_t*)buffer) + inlen;
        memcpy(bufptr, (((uint8_t*)state) + inlen), (RATE_BYTES - inlen));
        *bufptr ^= 0x80;
    }

    for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++) {
        tmp1 = state[i];
        tmp2 = state[j];
        state[i] ^= state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
        state[j] = tmp1 ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
        buffer[i] ^= tmp1;
        buffer[j] ^= tmp2;
    }
    memcpy(out, buffer, inlen);
}


/////////////                   Functions                          /////////////

void Initialize_Op(uint32_t* state, const uint8_t* key, const uint8_t* nonce)
{
    // load nonce into the rate-part of the state
    memcpy(state, nonce, NONCE_BYTES);
    // load key into the capacity-part of the sate
    memcpy((state + RATE_WORDS), key, KEY_BYTES);
    // execute SPARKLE with big number of steps
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}

void ProcessAssocData_Op(uint32_t* state, const uint8_t* in, size_t inlen)
{
    // check whether 'in' can be casted to uint32_t pointer
    int aligned = ((size_t)in) % UI32_ALIGN_BYTES == 0;
    // printf("Address of 'in': %p\n", in);

    // Main Authentication Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_aut_Op(state, in, aligned);
        // execute SPARKLE with slim number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        in += RATE_BYTES;
    }

    // Authentication of Last Block

    // addition of constant A0 or A1 to the state
    state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? CONST_A0 : CONST_A1);
    // combined Rho and rate-whitening (incl. padding)
    rho_whi_aut_last_Op(state, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}

void ProcessPlainText_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    // check whether 'in' and 'out' can be casted to uint32_t pointer
    int aligned = (((size_t)in) | ((size_t)out)) % UI32_ALIGN_BYTES == 0;
    // printf("Address of 'in' and 'out': %p, %p\n", in, out);

    // Main Encryption Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_enc_Op(state, out, in, aligned);
        // execute SPARKLE with slim number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        out += RATE_BYTES;
        in += RATE_BYTES;
    }

    // Encryption of Last Block

    // addition of constant M2 or M3 to the state
    state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
    // combined Rho and rate-whitening (incl. padding)
    rho_whi_enc_last_Op(state, out, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}

void Finalize_Op(uint32_t* state, const uint8_t* key)
{
    uint32_t buffer[TAG_WORDS];
    int i;

    // to prevent (potentially) unaligned memory accesses
    memcpy(buffer, key, KEY_BYTES);
    // add key to the capacity-part of the state
    for (i = 0; i < KEY_WORDS; i++)
        state[RATE_WORDS + i] ^= buffer[i];
}


// The GenerateTag function generates an authentication tag.

void GenerateTag_Op(uint32_t* state, uint8_t* tag)
{
    memcpy(tag, (state + RATE_WORDS), TAG_BYTES);
}

void ProcessCipherText_Op(uint32_t* state, uint8_t* out, const uint8_t* in, \
    size_t inlen)
{
    // check whether 'in' and 'out' can be casted to uint32_t pointer
    int aligned = (((size_t)in) | ((size_t)out)) % UI32_ALIGN_BYTES == 0;
    // printf("Address of 'in' and 'out': %p, %p\n", in, out);

    // Main Decryption Loop

    while (inlen > RATE_BYTES) {
        // combined Rho and rate-whitening operation
        rho_whi_dec_Op(state, out, in, aligned);
        // execute SPARKLE with slim number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
        inlen -= RATE_BYTES;
        out += RATE_BYTES;
        in += RATE_BYTES;
    }

    // Decryption of Last Block

    // addition of constant M2 or M3 to the state
    state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? CONST_M2 : CONST_M3);
    // combined Rho and rate-whitening (incl. padding)
    rho_whi_dec_last_Op(state, out, in, inlen);
    // execute SPARKLE with big number of steps
    sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
}