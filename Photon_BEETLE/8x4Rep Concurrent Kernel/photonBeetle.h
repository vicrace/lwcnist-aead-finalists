#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <algorithm>
#include <stdint.h>
//#include "endian/uint128_t.h"
#include <cstring>

//Utils
static inline constexpr uint32_t bswap32(const uint32_t a)
{
#if defined __GNUG__
	return __builtin_bswap32(a);
#else
	return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
		((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
#endif
}

//Photon

#if defined __SSSE3__
#include <tmmintrin.h>
#endif

constexpr size_t ROUNDS = 12ul;
constexpr uint8_t LS4B = 0x0f;
constexpr uint8_t IRP = 0b00010011 & LS4B;
//#define uint128_t unsigned __int128
//using uint128_t = unsigned __int128;

constexpr uint32_t RC[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

constexpr uint8_t M8[64] = {
  2,  4,  2,  11, 2,  8, 5,  6,  12, 9,  8,  13, 7,  7,  5,  2,
  4,  4,  13, 13, 9,  4, 13, 9,  1,  6,  5,  1,  12, 13, 15, 14,
  15, 12, 9,  13, 14, 5, 14, 13, 9,  14, 5,  15, 4,  12, 9,  6,
  12, 2,  2,  10, 3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3
};

constexpr uint8_t SBOX[256] = { 0xCC, 0xC5, 0xC6, 0xCB, 0xC9, 0xC0, 0xCA, 0xCD, 0xC3, 0xCE, 0xCF, 0xC8, 0xC4, 0xC7, 0xC1, 0xC2,
		0x5C, 0x55, 0x56, 0x5B, 0x59, 0x50, 0x5A, 0x5D, 0x53, 0x5E, 0x5F, 0x58, 0x54, 0x57, 0x51, 0x52, 0x6C, 0x65, 0x66, 0x6B,
		0x69, 0x60, 0x6A, 0x6D, 0x63, 0x6E, 0x6F, 0x68, 0x64, 0x67, 0x61, 0x62, 0xBC, 0xB5, 0xB6, 0xBB, 0xB9, 0xB0, 0xBA, 0xBD,
		0xB3, 0xBE, 0xBF, 0xB8, 0xB4, 0xB7, 0xB1, 0xB2, 0x9C, 0x95, 0x96, 0x9B, 0x99, 0x90, 0x9A, 0x9D, 0x93, 0x9E, 0x9F, 0x98,
		0x94, 0x97, 0x91, 0x92, 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2, 0xAC, 0xA5, 0xA6,
		0xAB, 0xA9, 0xA0, 0xAA, 0xAD, 0xA3, 0xAE, 0xAF, 0xA8, 0xA4, 0xA7, 0xA1, 0xA2, 0xDC, 0xD5, 0xD6, 0xDB, 0xD9, 0xD0, 0xDA,
		0xDD, 0xD3, 0xDE, 0xDF, 0xD8, 0xD4, 0xD7, 0xD1, 0xD2, 0x3C, 0x35, 0x36, 0x3B, 0x39, 0x30, 0x3A, 0x3D, 0x33, 0x3E, 0x3F, 0x38,
		0x34, 0x37, 0x31, 0x32, 0xEC, 0xE5, 0xE6, 0xEB, 0xE9, 0xE0, 0xEA, 0xED, 0xE3, 0xEE, 0xEF, 0xE8, 0xE4, 0xE7, 0xE1, 0xE2, 0xFC,
		0xF5, 0xF6, 0xFB, 0xF9, 0xF0, 0xFA, 0xFD, 0xF3, 0xFE, 0xFF, 0xF8, 0xF4, 0xF7, 0xF1, 0xF2, 0x8C, 0x85, 0x86, 0x8B, 0x89, 0x80,
		0x8A, 0x8D, 0x83, 0x8E, 0x8F, 0x88, 0x84, 0x87, 0x81, 0x82, 0x4C, 0x45, 0x46, 0x4B, 0x49, 0x40, 0x4A, 0x4D, 0x43, 0x4E, 0x4F,
		0x48, 0x44, 0x47, 0x41, 0x42, 0x7C, 0x75, 0x76, 0x7B, 0x79, 0x70, 0x7A, 0x7D, 0x73, 0x7E, 0x7F, 0x78, 0x74, 0x77, 0x71, 0x72,
		0x1C, 0x15, 0x16, 0x1B, 0x19, 0x10, 0x1A, 0x1D, 0x13, 0x1E, 0x1F, 0x18, 0x14, 0x17, 0x11, 0x12, 0x2C, 0x25, 0x26, 0x2B, 0x29,
		0x20, 0x2A, 0x2D, 0x23, 0x2E, 0x2F, 0x28, 0x24, 0x27, 0x21, 0x22 };

constexpr uint8_t GF16_MUL_TAB[256] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7,
		0x5, 0xB, 0x9, 0xF, 0xD, 0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, 0x0, 0x4, 0x8, 0xC, 0x3,
		0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, 0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3,
		0x6, 0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, 0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD,
		0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, 0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, 0x0, 0x9, 0x1,
		0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, 0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1,
		0xB, 0x6, 0xC, 0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, 0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE,
		0x2, 0xA, 0x6, 0x1, 0xD < 0xF, 0x3, 0x4, 0x8, 0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, 0x0,
		0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, 0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC,
		0x3, 0x8, 0x7, 0x5, 0xA };


static inline uint32_t rotl32(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
	c &= mask;
	return (n << c) | (n >> ((-c) & mask));
}

static inline uint32_t rotr32(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
	c &= mask;
	return (n >> c) | (n << ((-c) & mask));
}

inline static constexpr uint8_t gf16_mul(const uint8_t a, const uint8_t b)
{
	constexpr uint8_t br0[]{ 0, IRP };

	uint8_t x = a;
	uint8_t res = 0;

	for (size_t i = 0; i < 4; i++) {
		const uint8_t br1[]{ 0, x };

		const bool flg0 = (b >> i) & 0b1;
		const bool flg1 = (x >> 3) & 0b1;

		res ^= br1[flg0];

		x <<= 1;
		x ^= br0[flg1];
	}

	return res & LS4B;
}


inline static void add_constant(uint8_t* const state, const size_t r)
{
	const size_t off = r << 3;

	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));


	for (size_t i = 0; i < 8; i++) {
		tmp[i] = bswap32(tmp[i]);
	}

	for (size_t i = 0; i < 8; i++) {
		tmp[i] ^= RC[off + i];
	}
	memcpy(state, tmp, sizeof(tmp));
}

inline static void subcells(uint8_t* const state)
{
	for (size_t i = 0; i < 32; i++) {
		state[i] = SBOX[state[i]];
	}
}

inline static void shift_rows(uint8_t* const state)
{
	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));

	for (size_t i = 0; i < 8; i++) {
		if (ENDIAN == 1) { //little endian
			tmp[i] = rotr32(tmp[i], i * 4);
		}
		else { //big endian
			tmp[i] = rotl32(tmp[i], i * 4);
		}
	}

	memcpy(state, tmp, sizeof(tmp));
}

inline static void mix_column_serial_inner(uint8_t* const state)
{
	uint8_t s_prime[64]{};

	for (size_t i = 0; i < 8; i++) {
		const size_t off = i * 8;
		for (size_t k = 0; k < 8; k++) {
			for (size_t j = 0; j < 8; j++) {
				const uint8_t idx = (M8[off + k] << 4) | (state[(k * 8) + j] & LS4B);
				s_prime[off + j] ^= GF16_MUL_TAB[idx];
			}
		}
	}

	memcpy(state, s_prime, sizeof(s_prime));
}


inline static void mix_column_serial(uint8_t* const state)
{
	uint8_t tmp[64];

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && defined __SSSE3__

	constexpr uint32_t mask0 = 0x0f0f0f0fu;
	constexpr uint32_t mask1 = mask0 << 4;
	constexpr uint64_t mask2 = 0x0703060205010400ul;

	for (size_t i = 0; i < 8; i++) {
		uint32_t row;
		std::memcpy(&row, state + i * sizeof(row), sizeof(row));

		const auto t0 = row & mask0;
		const auto t1 = (row & mask1) >> 4;

		const uint64_t t2 = ((uint64_t)t1 << 32) | (uint64_t)t0;
		const uint64_t t3 = (uint64_t)_mm_shuffle_pi8((__m64)t2, (__m64)mask2);

		std::memcpy(tmp + i * sizeof(t3), &t3, sizeof(t3));
	}

#else

	for (size_t i = 0; i < 32; i++) {
		tmp[2 * i] = state[i] & LS4B;
		tmp[2 * i + 1] = state[i] >> 4;
	}

	mix_column_serial_inner(tmp);
#endif

	for (size_t i = 0; i < 32; i++) {
		state[i] = (tmp[2 * i + 1] << 4) | tmp[2 * i];
	}
}

inline static void photon256(uint8_t* const state)
{
	for (size_t i = 0; i < ROUNDS; i++) {
		add_constant(state, i);
		subcells(state);
		shift_rows(state);
		mix_column_serial(state);
	}
}

//common
// Compile-time check for ensuring that RATE ∈ {4, 16}
static bool check_rate(const size_t rate)
{
	return (rate == 4) || (rate == 16);
}

// Compile-time check for ensuring that OUT ∈ {16, 32}
static bool check_out(const size_t out)
{
	return (out == 16) || (out == 32);
}

inline static void
absorb(uint8_t* const state,     // 8x4 permutation state
	const uint8_t* const msg, // input message to be absorbed
	const size_t mlen,                   // len(msg) | >= 0
	const uint8_t C,
	const size_t RATE// domain seperation constant
)
{
	if (check_rate(RATE)) {

		if (RATE == 4) {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256(state);

				uint32_t rate;
				memcpy(&rate, state, RATE);

				uint32_t mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256(state);

				if (ENDIAN == 1) {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 1u << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 16777216u >> (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}
		else {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256(state);

				unsigned rate;
				memcpy(&rate, state, RATE);

				unsigned mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256(state);

				if (ENDIAN == 1) {

					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << ((15 - rm_bytes) * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}

		// add domain seperation constant
		state[31] ^= (C << 5);
	}
}

//8x4 permutation state
inline static void gen_tag(uint8_t* const state, uint8_t* const tag, size_t out)
{
	if (check_out(out)) {
		if (out == 16) {
			photon256(state);
			memcpy(tag, state, out);
		}
		else {
			photon256(state);
			memcpy(tag, state, out / 2);

			photon256(state);
			memcpy(tag + (out / 2), state, out / 2);
		}
	}
}


inline static void shuffle(const uint8_t* const __restrict state, uint8_t* const __restrict shuffled)
{
	if (check_rate(R)) {
		if (R == 4) {
			if (ENDIAN == 1) {
				uint16_t s1;
				memcpy(&s1, state, R / 2);

				const auto s1_prime = rotr32(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
			}
			else {
				const uint16_t s1 = (static_cast<uint16_t>(state[1]) << 8) |
					(static_cast<uint16_t>(state[0]) << 0);

				const auto s1_prime = rotl32(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				shuffled[2] = static_cast<uint8_t>(s1_prime);
				shuffled[3] = static_cast<uint8_t>(s1_prime >> 8);
			}
		}
		else {
			if (ENDIAN == 1) {
				uint64_t s1;
				memcpy(&s1, state, R / 2);

				const auto s1_prime = rotr32(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
			}
			else {
				uint64_t s1;
				for (size_t i = 0; i < R / 2; i++) {
					s1 |= static_cast<uint64_t>(state[i]) << (i * 8);
				}

				const auto s1_prime = rotr32(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);

				for (size_t i = 0; i < R / 2; i++) {
					shuffled[(R / 2) + i] = static_cast<uint8_t>(s1_prime >> (i * 8));
				}
			}
		}
	}
}

inline static void rho(uint8_t* const __restrict state,     // 8x4 permutation state
	const uint8_t* const __restrict txt, // plain text
	uint8_t* const __restrict enc,       // encrypted bytes
	const size_t tlen)
{
	if (check_rate(R)) {
		uint8_t shuffled[R];
		shuffle(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
		for (size_t i = 0; i < tlen; i++) {
			enc[i] = shuffled[i] ^ txt[i];
			state[i] ^= txt[i];
		}

		constexpr uint8_t br[]{ 0, 1 };
		state[tlen] ^= br[tlen < R];
	}
}

inline static void inv_rho(uint8_t* const __restrict state,     // 8x4 permutation state
	const uint8_t* const __restrict enc, // encrypted text
	uint8_t* const __restrict txt,       // plain text
	const size_t tlen
)
{
	if (check_rate(R)) {
		uint8_t shuffled[R];
		shuffle(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
		for (size_t i = 0; i < tlen; i++) {
			txt[i] = shuffled[i] ^ enc[i];
			state[i] ^= txt[i];
		}

		constexpr uint8_t br[]{ 0, 1 };
		state[tlen] ^= br[tlen < R];
	}
}

constexpr size_t KEY_LEN = 16ul;
constexpr size_t NONCE_LEN = 16ul;
constexpr size_t TAG_LEN = 16ul;


inline static bool verify_tag(const uint8_t* const __restrict expected, const uint8_t* const __restrict computed)
{
#if __SIZEOF_INT128__ == 16

	using uint128_t = unsigned __int128;
	uint128_t v0, v1;

	std::memcpy(&v0, expected, sizeof(v0));
	std::memcpy(&v1, computed, sizeof(v1));

	return !static_cast<bool>(v0 ^ v1);

#else

	uint64_t v0_hi, v0_lo;
	memcpy(&v0_lo, expected, sizeof(v0_lo));
	memcpy(&v0_hi, expected + 8, sizeof(v0_hi));

	uint64_t v1_hi, v1_lo;
	memcpy(&v1_lo, computed, sizeof(v1_lo));
	memcpy(&v1_hi, computed + 8, sizeof(v1_hi));

	return !(static_cast<bool>(v0_lo ^ v1_lo) | static_cast<bool>(v0_hi ^ v1_hi));

#endif
}



//////////////////////////////////////////////////////////////////////////////
/////////////////              GPU                         ///////////////////

__device__ uint32_t bswap32G(const uint32_t a)
{
#if defined __GNUG__
	return __builtin_bswap32(a);
#else
	return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
		((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
#endif
}


__device__ size_t ROUNDSG = 12ul;
__device__ uint8_t LS4BG = 0x0f;
__device__ uint8_t IRPG = 0b00010011 & LS4B;
//#define uint128_t unsigned __int128
//using uint128_t = unsigned __int128;

__device__ uint32_t RCG[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

__device__ uint8_t M8G[64] = {
  2,  4,  2,  11, 2,  8, 5,  6,  12, 9,  8,  13, 7,  7,  5,  2,
  4,  4,  13, 13, 9,  4, 13, 9,  1,  6,  5,  1,  12, 13, 15, 14,
  15, 12, 9,  13, 14, 5, 14, 13, 9,  14, 5,  15, 4,  12, 9,  6,
  12, 2,  2,  10, 3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3
};

__device__ uint8_t SBOXG[256] = { 0xCC, 0xC5, 0xC6, 0xCB, 0xC9, 0xC0, 0xCA, 0xCD, 0xC3, 0xCE, 0xCF, 0xC8, 0xC4, 0xC7, 0xC1, 0xC2,
		0x5C, 0x55, 0x56, 0x5B, 0x59, 0x50, 0x5A, 0x5D, 0x53, 0x5E, 0x5F, 0x58, 0x54, 0x57, 0x51, 0x52, 0x6C, 0x65, 0x66, 0x6B,
		0x69, 0x60, 0x6A, 0x6D, 0x63, 0x6E, 0x6F, 0x68, 0x64, 0x67, 0x61, 0x62, 0xBC, 0xB5, 0xB6, 0xBB, 0xB9, 0xB0, 0xBA, 0xBD,
		0xB3, 0xBE, 0xBF, 0xB8, 0xB4, 0xB7, 0xB1, 0xB2, 0x9C, 0x95, 0x96, 0x9B, 0x99, 0x90, 0x9A, 0x9D, 0x93, 0x9E, 0x9F, 0x98,
		0x94, 0x97, 0x91, 0x92, 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2, 0xAC, 0xA5, 0xA6,
		0xAB, 0xA9, 0xA0, 0xAA, 0xAD, 0xA3, 0xAE, 0xAF, 0xA8, 0xA4, 0xA7, 0xA1, 0xA2, 0xDC, 0xD5, 0xD6, 0xDB, 0xD9, 0xD0, 0xDA,
		0xDD, 0xD3, 0xDE, 0xDF, 0xD8, 0xD4, 0xD7, 0xD1, 0xD2, 0x3C, 0x35, 0x36, 0x3B, 0x39, 0x30, 0x3A, 0x3D, 0x33, 0x3E, 0x3F, 0x38,
		0x34, 0x37, 0x31, 0x32, 0xEC, 0xE5, 0xE6, 0xEB, 0xE9, 0xE0, 0xEA, 0xED, 0xE3, 0xEE, 0xEF, 0xE8, 0xE4, 0xE7, 0xE1, 0xE2, 0xFC,
		0xF5, 0xF6, 0xFB, 0xF9, 0xF0, 0xFA, 0xFD, 0xF3, 0xFE, 0xFF, 0xF8, 0xF4, 0xF7, 0xF1, 0xF2, 0x8C, 0x85, 0x86, 0x8B, 0x89, 0x80,
		0x8A, 0x8D, 0x83, 0x8E, 0x8F, 0x88, 0x84, 0x87, 0x81, 0x82, 0x4C, 0x45, 0x46, 0x4B, 0x49, 0x40, 0x4A, 0x4D, 0x43, 0x4E, 0x4F,
		0x48, 0x44, 0x47, 0x41, 0x42, 0x7C, 0x75, 0x76, 0x7B, 0x79, 0x70, 0x7A, 0x7D, 0x73, 0x7E, 0x7F, 0x78, 0x74, 0x77, 0x71, 0x72,
		0x1C, 0x15, 0x16, 0x1B, 0x19, 0x10, 0x1A, 0x1D, 0x13, 0x1E, 0x1F, 0x18, 0x14, 0x17, 0x11, 0x12, 0x2C, 0x25, 0x26, 0x2B, 0x29,
		0x20, 0x2A, 0x2D, 0x23, 0x2E, 0x2F, 0x28, 0x24, 0x27, 0x21, 0x22 };

__device__ const uint8_t GF16_MUL_TABG[256] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7,
		0x5, 0xB, 0x9, 0xF, 0xD, 0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, 0x0, 0x4, 0x8, 0xC, 0x3,
		0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, 0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3,
		0x6, 0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, 0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD,
		0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, 0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, 0x0, 0x9, 0x1,
		0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, 0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1,
		0xB, 0x6, 0xC, 0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, 0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE,
		0x2, 0xA, 0x6, 0x1, 0xD < 0xF, 0x3, 0x4, 0x8, 0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, 0x0,
		0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, 0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC,
		0x3, 0x8, 0x7, 0x5, 0xA };


__device__ uint32_t rotl32G(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
	c &= mask;
	return (n << c) | (n >> ((-c) & mask));
}

__device__ uint32_t rotr32G(uint32_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
	c &= mask;
	return (n >> c) | (n << ((-c) & mask));
}


__device__ void add_constantG(uint8_t* const state, const size_t r)
{
	const size_t off = r << 3;

	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));


	for (size_t i = 0; i < 8; i++) {
		tmp[i] = bswap32G(tmp[i]);
	}

	for (size_t i = 0; i < 8; i++) {
		tmp[i] ^= RCG[off + i];
	}
	memcpy(state, tmp, sizeof(tmp));
}

__device__ void subcellsG(uint8_t* const state)
{
	for (size_t i = 0; i < 32; i ++) {
		state[i] = SBOXG[state[i]];
	}
}

__device__ void shift_rowsG(uint8_t* const state)
{
	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));

	for (size_t i = 0; i < 8; i++) {
		if (ENDIAN == 1) { //little endian
			tmp[i] = rotr32G(tmp[i], i * 4);
		}
		else { //big endian
			tmp[i] = rotl32G(tmp[i], i * 4);
		}
	}

	memcpy(state, tmp, sizeof(tmp));
}

__device__ void mix_column_serial_innerG(uint8_t* const state)
{
	uint8_t s_prime[64]{};

	for (size_t i = 0; i < 8; i++) {
		const size_t off = i * 8;
		for (size_t k = 0; k < 8; k++) {
			for (size_t j = 0; j < 8; j++) {
				const uint8_t idx = (M8G[off + k] << 4) | (state[(k * 8) + j] & LS4BG);
				s_prime[off + j] ^= GF16_MUL_TABG[idx];
			}
		}
	}

	memcpy(state, s_prime, sizeof(s_prime));
}


__device__ void mix_column_serialG(uint8_t* const state)
{
	uint8_t tmp[64];

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && defined __SSSE3__

	constexpr uint32_t mask0 = 0x0f0f0f0fu;
	constexpr uint32_t mask1 = mask0 << 4;
	constexpr uint64_t mask2 = 0x0703060205010400ul;

	for (size_t i = 0; i < 8; i++) {
		uint32_t row;
		std::memcpy(&row, state + i * sizeof(row), sizeof(row));

		const auto t0 = row & mask0;
		const auto t1 = (row & mask1) >> 4;

		const uint64_t t2 = ((uint64_t)t1 << 32) | (uint64_t)t0;
		const uint64_t t3 = (uint64_t)_mm_shuffle_pi8((__m64)t2, (__m64)mask2);

		std::memcpy(tmp + i * sizeof(t3), &t3, sizeof(t3));
}

#else

	for (size_t i = 0; i < 32; i++) {
		tmp[2 * i] = state[i] & LS4B;
		tmp[2 * i + 1] = state[i] >> 4;
	}

	mix_column_serial_innerG(tmp);
#endif

	for (size_t i = 0; i < 32; i++) {
		state[i] = (tmp[2 * i + 1] << 4) | tmp[2 * i];
	}
}

__device__ void photon256G(uint8_t* const state)
{
	for (size_t i = 0; i < ROUNDS; i++) {
		add_constantG(state, i);
		subcellsG(state);
		shift_rowsG(state);
		mix_column_serialG(state);
	}
}


__device__ bool check_rateG(const size_t rate)
{
	return (rate == 4) || (rate == 16);
}

// Compile-time check for ensuring that OUT ∈ {16, 32}
__device__ bool check_outG(const size_t out)
{
	return (out == 16) || (out == 32);
}

__device__ inline static void
absorbG(uint8_t* const state,     // 8x4 permutation state
	const uint8_t* const msg, // input message to be absorbed
	const size_t mlen,                   // len(msg) | >= 0
	const uint8_t C,
	const size_t RATE// domain seperation constant
)
{
	if (check_rateG(RATE)) {

		if (RATE == 4) {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256G(state);

				uint32_t rate;
				memcpy(&rate, state, RATE);

				uint32_t mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256G(state);

				if (ENDIAN == 1) {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 1u << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 16777216u >> (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}
		else {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256G(state);

				unsigned rate;
				memcpy(&rate, state, RATE);

				unsigned mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256G(state);

				if (ENDIAN == 1) {

					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << ((15 - rm_bytes) * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}

		// add domain seperation constant
		state[31] ^= (C << 5);
	}
}

//8x4 permutation state
__device__ inline static void gen_tagG(uint8_t* const state, uint8_t* const tag, size_t out)
{
	if (check_outG(out)) {
		if (out == 16) {
			photon256G(state);
			memcpy(tag, state, out);
		}
		else {
			photon256G(state);
			memcpy(tag, state, out / 2);

			photon256G(state);
			memcpy(tag + (out / 2), state, out / 2);
		}
	}
}


__device__ inline static void shuffleG(const uint8_t* const __restrict state, uint8_t* const __restrict shuffled)
{
	if (check_rateG(R)) {
		if (R == 4) {
			if (ENDIAN == 1) {
				uint16_t s1;
				memcpy(&s1, state, R / 2);

				const auto s1_prime = rotr32G(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
			}
			else {
				const uint16_t s1 = (static_cast<uint16_t>(state[1]) << 8) |
					(static_cast<uint16_t>(state[0]) << 0);

				const auto s1_prime = rotl32G(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				shuffled[2] = static_cast<uint8_t>(s1_prime);
				shuffled[3] = static_cast<uint8_t>(s1_prime >> 8);
			}
		}
		else {
			if (ENDIAN == 1) {
				uint64_t s1;
				memcpy(&s1, state, R / 2);

				const auto s1_prime = rotr32G(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);
				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
			}
			else {
				uint64_t s1;
				for (size_t i = 0; i < R / 2; i++) {
					s1 |= static_cast<uint64_t>(state[i]) << (i * 8);
				}

				const auto s1_prime = rotr32G(s1, 1);
				memcpy(shuffled, state + (R / 2), R / 2);

				for (size_t i = 0; i < R / 2; i++) {
					shuffled[(R / 2) + i] = static_cast<uint8_t>(s1_prime >> (i * 8));
				}
			}
		}
	}
}

__device__ inline static void rhoG(uint8_t* const __restrict state,     // 8x4 permutation state
	const uint8_t* const __restrict txt, // plain text
	uint8_t* const __restrict enc,       // encrypted bytes
	const size_t tlen)
{
	if (check_rateG(R)) {
		uint8_t shuffled[R];
		shuffleG(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
		for (size_t i = 0; i < tlen; i++) {
			enc[i] = shuffled[i] ^ txt[i];
			state[i] ^= txt[i];
		}

		constexpr uint8_t br[]{ 0, 1 };
		state[tlen] ^= br[tlen < R];
	}
}

__device__ inline static void inv_rhoG(uint8_t* const __restrict state,     // 8x4 permutation state
	const uint8_t* const __restrict enc, // encrypted text
	uint8_t* const __restrict txt,       // plain text
	const size_t tlen
)
{
	if (check_rateG(R)) {
		uint8_t shuffled[R];
		shuffleG(state, shuffled);

#if defined __clang__
#pragma unroll
#elif defined __GNUG__
#pragma GCC ivdep
#endif
		for (size_t i = 0; i < tlen; i++) {
			txt[i] = shuffled[i] ^ enc[i];
			state[i] ^= txt[i];
		}

		constexpr uint8_t br[]{ 0, 1 };
		state[tlen] ^= br[tlen < R];
	}
}

__device__  size_t KEY_LENG = 16ul;
__device__  size_t NONCE_LENG = 16ul;
__device__  size_t TAG_LENG = 16ul;


__device__ inline static bool verify_tagG(const uint8_t* const __restrict expected, const uint8_t* const __restrict computed)
{
#if __SIZEOF_INT128__ == 16

	using uint128_t = unsigned __int128;
	uint128_t v0, v1;

	std::memcpy(&v0, expected, sizeof(v0));
	std::memcpy(&v1, computed, sizeof(v1));

	return !static_cast<bool>(v0 ^ v1);

#else

	uint64_t v0_hi, v0_lo;
	memcpy(&v0_lo, expected, sizeof(v0_lo));
	memcpy(&v0_hi, expected + 8, sizeof(v0_hi));

	uint64_t v1_hi, v1_lo;
	memcpy(&v1_lo, computed, sizeof(v1_lo));
	memcpy(&v1_hi, computed + 8, sizeof(v1_hi));

	return !(static_cast<bool>(v0_lo ^ v1_lo) | static_cast<bool>(v0_hi ^ v1_hi));

#endif
}





//////////////////////////////////////////////////////////////////////////////
/////////////////              GPU    Optimisation                     ///////////////////

__device__ const uint32_t RCG_Op[96] = {
  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
};

__device__ const uint8_t M8G_Op[64] = {
  2,  4,  2,  11, 2,  8, 5,  6,  12, 9,  8,  13, 7,  7,  5,  2,
  4,  4,  13, 13, 9,  4, 13, 9,  1,  6,  5,  1,  12, 13, 15, 14,
  15, 12, 9,  13, 14, 5, 14, 13, 9,  14, 5,  15, 4,  12, 9,  6,
  12, 2,  2,  10, 3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3
};

__device__ const uint8_t SBOXG_Op[256] = { 0xCC, 0xC5, 0xC6, 0xCB, 0xC9, 0xC0, 0xCA, 0xCD, 0xC3, 0xCE, 0xCF, 0xC8, 0xC4, 0xC7, 0xC1, 0xC2,
		0x5C, 0x55, 0x56, 0x5B, 0x59, 0x50, 0x5A, 0x5D, 0x53, 0x5E, 0x5F, 0x58, 0x54, 0x57, 0x51, 0x52, 0x6C, 0x65, 0x66, 0x6B,
		0x69, 0x60, 0x6A, 0x6D, 0x63, 0x6E, 0x6F, 0x68, 0x64, 0x67, 0x61, 0x62, 0xBC, 0xB5, 0xB6, 0xBB, 0xB9, 0xB0, 0xBA, 0xBD,
		0xB3, 0xBE, 0xBF, 0xB8, 0xB4, 0xB7, 0xB1, 0xB2, 0x9C, 0x95, 0x96, 0x9B, 0x99, 0x90, 0x9A, 0x9D, 0x93, 0x9E, 0x9F, 0x98,
		0x94, 0x97, 0x91, 0x92, 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2, 0xAC, 0xA5, 0xA6,
		0xAB, 0xA9, 0xA0, 0xAA, 0xAD, 0xA3, 0xAE, 0xAF, 0xA8, 0xA4, 0xA7, 0xA1, 0xA2, 0xDC, 0xD5, 0xD6, 0xDB, 0xD9, 0xD0, 0xDA,
		0xDD, 0xD3, 0xDE, 0xDF, 0xD8, 0xD4, 0xD7, 0xD1, 0xD2, 0x3C, 0x35, 0x36, 0x3B, 0x39, 0x30, 0x3A, 0x3D, 0x33, 0x3E, 0x3F, 0x38,
		0x34, 0x37, 0x31, 0x32, 0xEC, 0xE5, 0xE6, 0xEB, 0xE9, 0xE0, 0xEA, 0xED, 0xE3, 0xEE, 0xEF, 0xE8, 0xE4, 0xE7, 0xE1, 0xE2, 0xFC,
		0xF5, 0xF6, 0xFB, 0xF9, 0xF0, 0xFA, 0xFD, 0xF3, 0xFE, 0xFF, 0xF8, 0xF4, 0xF7, 0xF1, 0xF2, 0x8C, 0x85, 0x86, 0x8B, 0x89, 0x80,
		0x8A, 0x8D, 0x83, 0x8E, 0x8F, 0x88, 0x84, 0x87, 0x81, 0x82, 0x4C, 0x45, 0x46, 0x4B, 0x49, 0x40, 0x4A, 0x4D, 0x43, 0x4E, 0x4F,
		0x48, 0x44, 0x47, 0x41, 0x42, 0x7C, 0x75, 0x76, 0x7B, 0x79, 0x70, 0x7A, 0x7D, 0x73, 0x7E, 0x7F, 0x78, 0x74, 0x77, 0x71, 0x72,
		0x1C, 0x15, 0x16, 0x1B, 0x19, 0x10, 0x1A, 0x1D, 0x13, 0x1E, 0x1F, 0x18, 0x14, 0x17, 0x11, 0x12, 0x2C, 0x25, 0x26, 0x2B, 0x29,
		0x20, 0x2A, 0x2D, 0x23, 0x2E, 0x2F, 0x28, 0x24, 0x27, 0x21, 0x22 };

__device__ const uint8_t GF16_MUL_TABG_Op[256] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7,
		0x5, 0xB, 0x9, 0xF, 0xD, 0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, 0x0, 0x4, 0x8, 0xC, 0x3,
		0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, 0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3,
		0x6, 0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, 0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD,
		0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, 0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, 0x0, 0x9, 0x1,
		0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, 0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1,
		0xB, 0x6, 0xC, 0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, 0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE,
		0x2, 0xA, 0x6, 0x1, 0xD < 0xF, 0x3, 0x4, 0x8, 0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, 0x0,
		0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, 0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC,
		0x3, 0x8, 0x7, 0x5, 0xA };


__device__ void add_constantG_Op(uint8_t* const state, const size_t r)
{
	const size_t off = r << 3;

	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));


	for (size_t i = 0; i < 8; i++) {
		tmp[i] = bswap32G(tmp[i]);
	}

	for (size_t i = 0; i < 8; i += 2) {
		tmp[i] ^= RCG_Op[off + i];
		tmp[i + 1] ^= RCG_Op[off + i + 1];
	}
	memcpy(state, tmp, sizeof(tmp));
}

__device__ void subcellsG_Op(uint8_t* const state)
{
	for (size_t i = 0; i < 32; i ++) {
		state[i] = SBOXG_Op[state[i]];
	}
}

__device__ void shift_rowsG_Op(uint8_t* const state)
{
	uint32_t tmp[8];
	memcpy(tmp, state, sizeof(tmp));

	for (size_t i = 0; i < 8; i++) {
		if (ENDIAN == 1) { //little endian
			tmp[i] = rotr32G(tmp[i], i * 4);
		}
		else { //big endian
			tmp[i] = rotl32G(tmp[i], i * 4);
		}
	}

	memcpy(state, tmp, sizeof(tmp));
}

__device__ void mix_column_serial_innerG_Op(uint8_t* const state)
{
	uint8_t s_prime[64]{};

	for (size_t i = 0; i < 8; i++) {
		const size_t off = i * 8;
		for (size_t k = 0; k < 8; k++) {
			for (size_t j = 0; j < 8; j++) {
				const uint8_t idx = (M8G_Op[off + k] << 4) | (state[(k * 8) + j] & LS4BG);
				s_prime[off + j] ^= GF16_MUL_TABG_Op[idx];
			}
		}
	}

	memcpy(state, s_prime, sizeof(s_prime));
}


__device__ void mix_column_serialG_Op(uint8_t* const state)
{
	uint8_t tmp[64];

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && defined __SSSE3__

	constexpr uint32_t mask0 = 0x0f0f0f0fu;
	constexpr uint32_t mask1 = mask0 << 4;
	constexpr uint64_t mask2 = 0x0703060205010400ul;

	for (size_t i = 0; i < 8; i++) {
		uint32_t row;
		std::memcpy(&row, state + i * sizeof(row), sizeof(row));

		const auto t0 = row & mask0;
		const auto t1 = (row & mask1) >> 4;

		const uint64_t t2 = ((uint64_t)t1 << 32) | (uint64_t)t0;
		const uint64_t t3 = (uint64_t)_mm_shuffle_pi8((__m64)t2, (__m64)mask2);

		std::memcpy(tmp + i * sizeof(t3), &t3, sizeof(t3));
	}

#else

	for (size_t i = 0; i < 32; i++) {
		tmp[2 * i] = state[i] & LS4B;
		tmp[2 * i + 1] = state[i] >> 4;
	}

	mix_column_serial_innerG_Op(tmp);
#endif

	for (size_t i = 0; i < 32; i++) {
		state[i] = (tmp[2 * i + 1] << 4) | tmp[2 * i];
	}
}

__device__ void photon256G_Op(uint8_t* const state)
{
	for (size_t i = 0; i < ROUNDS; i++) {
		add_constantG_Op(state, i);
		subcellsG_Op(state);
		shift_rowsG_Op(state);
		mix_column_serialG(state);
	}
}

__device__ inline static void
absorbG_Op(uint8_t* const state,     // 8x4 permutation state
	const uint8_t* const msg, // input message to be absorbed
	const size_t mlen,                   // len(msg) | >= 0
	const uint8_t C,
	const size_t RATE// domain seperation constant
)
{
	if (check_rateG(RATE)) {

		if (RATE == 4) {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256G_Op(state);

				uint32_t rate;
				memcpy(&rate, state, RATE);

				uint32_t mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256G_Op(state);

				if (ENDIAN == 1) {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 1u << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					uint32_t rate;
					memcpy(&rate, state, RATE);

					uint32_t mword = 16777216u >> (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}
		else {
			const size_t full_blk_cnt = mlen / RATE;
			const size_t full_blk_bytes = full_blk_cnt * RATE;

			size_t off = 0;
			while (off < full_blk_bytes) {
				photon256G_Op(state);

				unsigned rate;
				memcpy(&rate, state, RATE);

				unsigned mword;
				memcpy(&mword, msg + off, RATE);

				const auto nrate = rate ^ mword;
				memcpy(state, &nrate, RATE);

				off += RATE;
			}

			const size_t rm_bytes = mlen - off;
			if (rm_bytes > 0) {
				photon256G_Op(state);

				if (ENDIAN == 1) {

					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << (rm_bytes * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
				else {
					unsigned rate;
					memcpy(&rate, state, RATE);

					unsigned mword = static_cast<unsigned>(1) << ((15 - rm_bytes) * 8);
					memcpy(&mword, msg + off, rm_bytes);

					const auto nrate = rate ^ mword;
					memcpy(state, &nrate, RATE);
				}
			}
		}

		// add domain seperation constant
		state[31] ^= (C << 5);
	}
}

//8x4 permutation state
__device__ inline static void gen_tagG_Op(uint8_t* const state, uint8_t* const tag, size_t out)
{
	if (check_outG(out)) {
		if (out == 16) {
			photon256G_Op(state);
			memcpy(tag, state, out);
		}
		else {
			photon256G_Op(state);
			memcpy(tag, state, out / 2);

			photon256G_Op(state);
			memcpy(tag + (out / 2), state, out / 2);
		}
	}
}



////////////////////////////////////////////////////////////////////////////////
///////////////////              GPU                         ///////////////////
//
//__device__ uint32_t bswap32G(const uint32_t a)
//{
//#if defined __GNUG__
//	return __builtin_bswap32(a);
//#else
//	return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
//		((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
//#endif
//}
//
//
//__device__ size_t ROUNDSG = 12ul;
//__device__ uint8_t LS4BG = 0x0f;
//__device__ uint8_t IRPG = 0b00010011 & LS4B;
////#define uint128_t unsigned __int128
////using uint128_t = unsigned __int128;
//
//__device__ uint32_t RCG[96] = {
//  1,  0,  2,  6,  14, 15, 13, 9,  3,  2,  0, 4,  12, 13, 15, 11, 7,  6,  4,  0,
//  8,  9,  11, 15, 14, 15, 13, 9,  1,  0,  2, 6,  13, 12, 14, 10, 2,  3,  1,  5,
//  11, 10, 8,  12, 4,  5,  7,  3,  6,  7,  5, 1,  9,  8,  10, 14, 12, 13, 15, 11,
//  3,  2,  0,  4,  9,  8,  10, 14, 6,  7,  5, 1,  2,  3,  1,  5,  13, 12, 14, 10,
//  5,  4,  6,  2,  10, 11, 9,  13, 10, 11, 9, 13, 5,  4,  6,  2
//};
//
//__device__ uint8_t M8G[64] = {
//  2,  4,  2,  11, 2,  8, 5,  6,  12, 9,  8,  13, 7,  7,  5,  2,
//  4,  4,  13, 13, 9,  4, 13, 9,  1,  6,  5,  1,  12, 13, 15, 14,
//  15, 12, 9,  13, 14, 5, 14, 13, 9,  14, 5,  15, 4,  12, 9,  6,
//  12, 2,  2,  10, 3,  1, 1,  14, 15, 1,  13, 10, 5,  10, 2,  3
//};
//
//__device__ uint8_t SBOXG[256] = { 0xCC, 0xC5, 0xC6, 0xCB, 0xC9, 0xC0, 0xCA, 0xCD, 0xC3, 0xCE, 0xCF, 0xC8, 0xC4, 0xC7, 0xC1, 0xC2,
//		0x5C, 0x55, 0x56, 0x5B, 0x59, 0x50, 0x5A, 0x5D, 0x53, 0x5E, 0x5F, 0x58, 0x54, 0x57, 0x51, 0x52, 0x6C, 0x65, 0x66, 0x6B,
//		0x69, 0x60, 0x6A, 0x6D, 0x63, 0x6E, 0x6F, 0x68, 0x64, 0x67, 0x61, 0x62, 0xBC, 0xB5, 0xB6, 0xBB, 0xB9, 0xB0, 0xBA, 0xBD,
//		0xB3, 0xBE, 0xBF, 0xB8, 0xB4, 0xB7, 0xB1, 0xB2, 0x9C, 0x95, 0x96, 0x9B, 0x99, 0x90, 0x9A, 0x9D, 0x93, 0x9E, 0x9F, 0x98,
//		0x94, 0x97, 0x91, 0x92, 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2, 0xAC, 0xA5, 0xA6,
//		0xAB, 0xA9, 0xA0, 0xAA, 0xAD, 0xA3, 0xAE, 0xAF, 0xA8, 0xA4, 0xA7, 0xA1, 0xA2, 0xDC, 0xD5, 0xD6, 0xDB, 0xD9, 0xD0, 0xDA,
//		0xDD, 0xD3, 0xDE, 0xDF, 0xD8, 0xD4, 0xD7, 0xD1, 0xD2, 0x3C, 0x35, 0x36, 0x3B, 0x39, 0x30, 0x3A, 0x3D, 0x33, 0x3E, 0x3F, 0x38,
//		0x34, 0x37, 0x31, 0x32, 0xEC, 0xE5, 0xE6, 0xEB, 0xE9, 0xE0, 0xEA, 0xED, 0xE3, 0xEE, 0xEF, 0xE8, 0xE4, 0xE7, 0xE1, 0xE2, 0xFC,
//		0xF5, 0xF6, 0xFB, 0xF9, 0xF0, 0xFA, 0xFD, 0xF3, 0xFE, 0xFF, 0xF8, 0xF4, 0xF7, 0xF1, 0xF2, 0x8C, 0x85, 0x86, 0x8B, 0x89, 0x80,
//		0x8A, 0x8D, 0x83, 0x8E, 0x8F, 0x88, 0x84, 0x87, 0x81, 0x82, 0x4C, 0x45, 0x46, 0x4B, 0x49, 0x40, 0x4A, 0x4D, 0x43, 0x4E, 0x4F,
//		0x48, 0x44, 0x47, 0x41, 0x42, 0x7C, 0x75, 0x76, 0x7B, 0x79, 0x70, 0x7A, 0x7D, 0x73, 0x7E, 0x7F, 0x78, 0x74, 0x77, 0x71, 0x72,
//		0x1C, 0x15, 0x16, 0x1B, 0x19, 0x10, 0x1A, 0x1D, 0x13, 0x1E, 0x1F, 0x18, 0x14, 0x17, 0x11, 0x12, 0x2C, 0x25, 0x26, 0x2B, 0x29,
//		0x20, 0x2A, 0x2D, 0x23, 0x2E, 0x2F, 0x28, 0x24, 0x27, 0x21, 0x22 };
//
//__device__ uint8_t GF16_MUL_TABG[256] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 ,0x0, 0x0 ,0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
//		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7,
//		0x5, 0xB, 0x9, 0xF, 0xD, 0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2, 0x0, 0x4, 0x8, 0xC, 0x3,
//		0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9, 0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3,
//		0x6, 0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4, 0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD,
//		0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB, 0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1, 0x0, 0x9, 0x1,
//		0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE, 0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1,
//		0xB, 0x6, 0xC, 0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3, 0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE,
//		0x2, 0xA, 0x6, 0x1, 0xD < 0xF, 0x3, 0x4, 0x8, 0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7, 0x0,
//		0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5, 0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC,
//		0x3, 0x8, 0x7, 0x5, 0xA };
//
//
//__device__ uint32_t rotl32G(uint32_t n, unsigned int c)
//{
//	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
//	c &= mask;
//	return (n << c) | (n >> ((-c) & mask));
//}
//
//__device__ uint32_t rotr32G(uint32_t n, unsigned int c)
//{
//	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
//	c &= mask;
//	return (n >> c) | (n << ((-c) & mask));
//}
//
//
//__device__ void add_constantG(uint8_t* const state, const size_t r)
//{
//	const size_t off = r << 3;
//
//	uint32_t tmp[8];
//	memcpy(tmp, state, sizeof(tmp));
//
//
//	for (size_t i = 0; i < 8; i++) {
//		tmp[i] = bswap32G(tmp[i]);
//	}
//
//	for (size_t i = 0; i < 8; i++) {
//		tmp[i] ^= RCG[off + i];
//	}
//	memcpy(state, tmp, sizeof(tmp));
//}
//
//__device__ void subcellsG(uint8_t* const state)
//{
//	for (size_t i = 0; i < 32; i++) {
//		state[i] = SBOXG[state[i]];
//	}
//}
//
//__device__ void shift_rowsG(uint8_t* const state)
//{
//	uint32_t tmp[8];
//	memcpy(tmp, state, sizeof(tmp));
//
//	for (size_t i = 0; i < 8; i++) {
//		if constexpr (ENDIAN == 1) { //little endian
//			tmp[i] = rotr32G(tmp[i], i * 4);
//		}
//		else { //big endian
//			tmp[i] = rotl32G(tmp[i], i * 4);
//		}
//	}
//
//	memcpy(state, tmp, sizeof(tmp));
//}
//
//__device__ void mix_column_serial_innerG(uint8_t* const state)
//{
//	uint8_t s_prime[64]{};
//
//	for (size_t i = 0; i < 8; i++) {
//		const size_t off = i * 8;
//		for (size_t k = 0; k < 8; k++) {
//			for (size_t j = 0; j < 8; j++) {
//				const uint8_t idx = (M8G[off + k] << 4) | (state[(k * 8) + j] & LS4BG);
//				s_prime[off + j] ^= GF16_MUL_TABG[idx];
//			}
//		}
//	}
//
//	memcpy(state, s_prime, sizeof(s_prime));
//}
//
//
//__device__ void mix_column_serialG(uint8_t* const state)
//{
//	uint8_t tmp[64];
//
//#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && defined __SSSE3__
//
//	constexpr uint32_t mask0 = 0x0f0f0f0fu;
//	constexpr uint32_t mask1 = mask0 << 4;
//	constexpr uint64_t mask2 = 0x0703060205010400ul;
//
//	for (size_t i = 0; i < 8; i++) {
//		uint32_t row;
//		std::memcpy(&row, state + i * sizeof(row), sizeof(row));
//
//		const auto t0 = row & mask0;
//		const auto t1 = (row & mask1) >> 4;
//
//		const uint64_t t2 = ((uint64_t)t1 << 32) | (uint64_t)t0;
//		const uint64_t t3 = (uint64_t)_mm_shuffle_pi8((__m64)t2, (__m64)mask2);
//
//		std::memcpy(tmp + i * sizeof(t3), &t3, sizeof(t3));
//	}
//
//#else
//
//	for (size_t i = 0; i < 32; i++) {
//		tmp[2 * i] = state[i] & LS4B;
//		tmp[2 * i + 1] = state[i] >> 4;
//	}
//
//	mix_column_serial_innerG(tmp);
//#endif
//
//	for (size_t i = 0; i < 32; i++) {
//		state[i] = (tmp[2 * i + 1] << 4) | tmp[2 * i];
//	}
//}
//
//__device__ void photon256G(uint8_t* const state)
//{
//	for (size_t i = 0; i < ROUNDS; i++) {
//		add_constantG(state, i);
//		subcellsG(state);
//		shift_rowsG(state);
//		mix_column_serialG(state);
//	}
//}
//
//
//__device__ bool check_rateG(const size_t rate)
//{
//	return (rate == 4) || (rate == 16);
//}
//
//// Compile-time check for ensuring that OUT ∈ {16, 32}
//__device__ bool check_outG(const size_t out)
//{
//	return (out == 16) || (out == 32);
//}
//
//__device__ inline static void
//absorbG(uint8_t* const state,     // 8x4 permutation state
//	const uint8_t* const msg, // input message to be absorbed
//	const size_t mlen,                   // len(msg) | >= 0
//	const uint8_t C,
//	const size_t RATE// domain seperation constant
//)
//{
//	if (check_rateG(RATE)) {
//
//		if (RATE == 4) {
//			const size_t full_blk_cnt = mlen / RATE;
//			const size_t full_blk_bytes = full_blk_cnt * RATE;
//
//			size_t off = 0;
//			while (off < full_blk_bytes) {
//				photon256G(state);
//
//				uint32_t rate;
//				memcpy(&rate, state, RATE);
//
//				uint32_t mword;
//				memcpy(&mword, msg + off, RATE);
//
//				const auto nrate = rate ^ mword;
//				memcpy(state, &nrate, RATE);
//
//				off += RATE;
//			}
//
//			const size_t rm_bytes = mlen - off;
//			if (rm_bytes > 0) {
//				photon256G(state);
//
//				if constexpr (ENDIAN == 1) {
//					uint32_t rate;
//					memcpy(&rate, state, RATE);
//
//					uint32_t mword = 1u << (rm_bytes * 8);
//					memcpy(&mword, msg + off, rm_bytes);
//
//					const auto nrate = rate ^ mword;
//					memcpy(state, &nrate, RATE);
//				}
//				else {
//					uint32_t rate;
//					memcpy(&rate, state, RATE);
//
//					uint32_t mword = 16777216u >> (rm_bytes * 8);
//					memcpy(&mword, msg + off, rm_bytes);
//
//					const auto nrate = rate ^ mword;
//					memcpy(state, &nrate, RATE);
//				}
//			}
//		}
//		else {
//			const size_t full_blk_cnt = mlen / RATE;
//			const size_t full_blk_bytes = full_blk_cnt * RATE;
//
//			size_t off = 0;
//			while (off < full_blk_bytes) {
//				photon256G(state);
//
//				unsigned rate;
//				memcpy(&rate, state, RATE);
//
//				unsigned mword;
//				memcpy(&mword, msg + off, RATE);
//
//				const auto nrate = rate ^ mword;
//				memcpy(state, &nrate, RATE);
//
//				off += RATE;
//			}
//
//			const size_t rm_bytes = mlen - off;
//			if (rm_bytes > 0) {
//				photon256G(state);
//
//				if constexpr (ENDIAN == 1) {
//
//					unsigned rate;
//					memcpy(&rate, state, RATE);
//
//					unsigned mword = static_cast<unsigned>(1) << (rm_bytes * 8);
//					memcpy(&mword, msg + off, rm_bytes);
//
//					const auto nrate = rate ^ mword;
//					memcpy(state, &nrate, RATE);
//				}
//				else {
//					unsigned rate;
//					memcpy(&rate, state, RATE);
//
//					unsigned mword = static_cast<unsigned>(1) << ((15 - rm_bytes) * 8);
//					memcpy(&mword, msg + off, rm_bytes);
//
//					const auto nrate = rate ^ mword;
//					memcpy(state, &nrate, RATE);
//				}
//			}
//		}
//
//		// add domain seperation constant
//		state[31] ^= (C << 5);
//	}
//}
//
////8x4 permutation state
//__device__ inline static void gen_tagG(uint8_t* const state, uint8_t* const tag, size_t out)
//{
//	if (check_outG(out)) {
//		if (out == 16) {
//			photon256G(state);
//			memcpy(tag, state, out);
//		}
//		else {
//			photon256G(state);
//			memcpy(tag, state, out / 2);
//
//			photon256G(state);
//			memcpy(tag + (out / 2), state, out / 2);
//		}
//	}
//}
//
//
//__device__ inline static void shuffleG(const uint8_t* const __restrict state, uint8_t* const __restrict shuffled)
//{
//	if (check_rateG(R)) {
//		if (R == 4) {
//			if (ENDIAN == 1) {
//				uint16_t s1;
//				memcpy(&s1, state, R / 2);
//
//				const auto s1_prime = rotr32G(s1, 1);
//				memcpy(shuffled, state + (R / 2), R / 2);
//				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
//			}
//			else {
//				const uint16_t s1 = (static_cast<uint16_t>(state[1]) << 8) |
//					(static_cast<uint16_t>(state[0]) << 0);
//
//				const auto s1_prime = rotl32G(s1, 1);
//				memcpy(shuffled, state + (R / 2), R / 2);
//				shuffled[2] = static_cast<uint8_t>(s1_prime);
//				shuffled[3] = static_cast<uint8_t>(s1_prime >> 8);
//			}
//		}
//		else {
//			if (ENDIAN == 1) {
//				uint64_t s1;
//				memcpy(&s1, state, R / 2);
//
//				const auto s1_prime = rotr32G(s1, 1);
//				memcpy(shuffled, state + (R / 2), R / 2);
//				memcpy(shuffled + (R / 2), &s1_prime, R / 2);
//			}
//			else {
//				uint64_t s1;
//				for (size_t i = 0; i < R / 2; i++) {
//					s1 |= static_cast<uint64_t>(state[i]) << (i * 8);
//				}
//
//				const auto s1_prime = rotr32G(s1, 1);
//				memcpy(shuffled, state + (R / 2), R / 2);
//
//				for (size_t i = 0; i < R / 2; i++) {
//					shuffled[(R / 2) + i] = static_cast<uint8_t>(s1_prime >> (i * 8));
//				}
//			}
//		}
//	}
//}
//
//__device__ inline static void rhoG(uint8_t* const __restrict state,     // 8x4 permutation state
//	const uint8_t* const __restrict txt, // plain text
//	uint8_t* const __restrict enc,       // encrypted bytes
//	const size_t tlen)
//{
//	if (check_rateG(R)) {
//		uint8_t shuffled[R];
//		shuffleG(state, shuffled);
//
//#if defined __clang__
//#pragma unroll
//#elif defined __GNUG__
//#pragma GCC ivdep
//#endif
//		for (size_t i = 0; i < tlen; i++) {
//			enc[i] = shuffled[i] ^ txt[i];
//			state[i] ^= txt[i];
//		}
//
//		constexpr uint8_t br[]{ 0, 1 };
//		state[tlen] ^= br[tlen < R];
//	}
//}
//
//__device__ inline static void inv_rhoG(uint8_t* const __restrict state,     // 8x4 permutation state
//	const uint8_t* const __restrict enc, // encrypted text
//	uint8_t* const __restrict txt,       // plain text
//	const size_t tlen
//)
//{
//	if (check_rateG(R)) {
//		uint8_t shuffled[R];
//		shuffleG(state, shuffled);
//
//#if defined __clang__
//#pragma unroll
//#elif defined __GNUG__
//#pragma GCC ivdep
//#endif
//		for (size_t i = 0; i < tlen; i++) {
//			txt[i] = shuffled[i] ^ enc[i];
//			state[i] ^= txt[i];
//		}
//
//		constexpr uint8_t br[]{ 0, 1 };
//		state[tlen] ^= br[tlen < R];
//	}
//}
//
//__device__  size_t KEY_LENG = 16ul;
//__device__  size_t NONCE_LENG = 16ul;
//__device__  size_t TAG_LENG = 16ul;
//
//
//__device__ inline static bool verify_tagG(const uint8_t* const __restrict expected, const uint8_t* const __restrict computed)
//{
//#if __SIZEOF_INT128__ == 16
//
//	using uint128_t = unsigned __int128;
//	uint128_t v0, v1;
//
//	std::memcpy(&v0, expected, sizeof(v0));
//	std::memcpy(&v1, computed, sizeof(v1));
//
//	return !static_cast<bool>(v0 ^ v1);
//
//#else
//
//	uint64_t v0_hi, v0_lo;
//	memcpy(&v0_lo, expected, sizeof(v0_lo));
//	memcpy(&v0_hi, expected + 8, sizeof(v0_hi));
//
//	uint64_t v1_hi, v1_lo;
//	memcpy(&v1_lo, computed, sizeof(v1_lo));
//	memcpy(&v1_hi, computed + 8, sizeof(v1_hi));
//
//	return !(static_cast<bool>(v0_lo ^ v1_lo) | static_cast<bool>(v0_hi ^ v1_hi));
//
//#endif
//}