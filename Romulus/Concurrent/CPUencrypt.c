#include "romulusOp.c"
#include "romulusRef.h"

////////////      Romulus M, N, T Ref         //////////////////
int romulus_m_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	unsigned char s[16];
	unsigned char CNT[7];
	unsigned char T[16];
	const unsigned char* N;
	unsigned int n, t, i;
	unsigned char w;
	unsigned long long xlen;

	(void)nsec;
	N = npub;

	n = AD_BLK_LEN_ODD;
	t = AD_BLK_LEN_EVN;

	xlen = mlen;

	for (i = 0; i < n; i++) {
		s[i] = 0;
	}
	reset_lfsr_gf56(CNT);

	// Calculating the domain separation bits for the last block MAC TBC call depending on the length of M and AD
	w = 48;

	if (adlen == 0) {
		w = w ^ 2;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (n + t) < t) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == t) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (n + t) == 0) {
		w = w ^ 8;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (n + t) < n) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == n) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (n + t) < n) {
		w = w ^ 2;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (n + t) < t) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == t) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (n + t) == n) {
		w = w ^ 0;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (n + t) < t) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == t) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else {
		w = w ^ 10;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (n + t) < n) {
			w = w ^ 1;
		}
		else if (xlen % (n + t) == n) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}

	if (adlen == 0) { // AD is an empty string
		lfsr_gf56(CNT);
	}
	else while (adlen > 0) {
		adlen = ad_encryption(&ad, s, k, adlen, CNT, 40, n, t);
	}

	if ((w & 8) == 0) {
		xlen = ad2msg_encryption(&m, CNT, s, k, t, 44, xlen);
	}
	else if (mlen == 0) {
		lfsr_gf56(CNT);
	}
	while (xlen > 0) {
		xlen = ad_encryption(&m, s, k, xlen, CNT, 44, n, t);
	}
	nonce_encryption(N, CNT, s, k, t, w);


	// Tag generation 
	g8A(s, T);

	m = m - mlen;

	reset_lfsr_gf56(CNT);

	for (i = 0; i < n; i = i + 1) {
		s[i] = T[i];
	}

	n = MSG_BLK_LEN;
	*clen = mlen + n;



	if (mlen > 0) {
		nonce_encryption(N, CNT, s, k, t, 36);
		while (mlen > n) {
			mlen = msg_encryption(&m, &c, N, CNT, s, k, n, t, 36, mlen);
		}
		rho(m, c, s, mlen, 16);
		c = c + mlen;
		m = m + mlen;
	}

	// Tag Concatenation
	for (i = 0; i < 16; i = i + 1) {
		*(c + i) = T[i];
	}

	c = c - *clen;



	return 0;
}


int romulus_n_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	unsigned char s[16];
	unsigned char CNT[7];
	unsigned char T[16];
	const unsigned char* A;
	const unsigned char* I;
	const unsigned char* N;
	unsigned int n, t, i;
	char d = 0;

	(void)nsec;
	A = ad;
	I = m;
	N = npub;

	n = AD_BLK_LEN_ODD;
	t = AD_BLK_LEN_EVN;

	for (i = 0; i < n; i++) {
		s[i] = 0;
	}
	reset_lfsr_gf56(CNT);

	if (adlen == 0) { // AD is an empty string
		lfsr_gf56(CNT);
		nonce_encryption(N, CNT, s, k, t, 0x1a);
	}
	else while (adlen > 0) {
		if (adlen < n) { // The last block of AD is odd and incomplete
			adlen = ad_encryption(&A, s, k, adlen, CNT, 0x08, n, t);
			nonce_encryption(N, CNT, s, k, t, 0x1a);
		}
		else if (adlen == n) { // The last block of AD is odd and complete
			adlen = ad_encryption(&A, s, k, adlen, CNT, 0x08, n, t);
			nonce_encryption(N, CNT, s, k, t, 0x18);
		}
		else if (adlen < (n + t)) { // The last block of AD is even and incomplete
			adlen = ad_encryption(&A, s, k, adlen, CNT, 0x08, n, t);
			nonce_encryption(N, CNT, s, k, t, 0x1a);
		}
		else if (adlen == (n + t)) { // The last block of AD is even and complete
			adlen = ad_encryption(&A, s, k, adlen, CNT, 0x08, n, t);
			nonce_encryption(N, CNT, s, k, t, 0x18);
		}
		else { // A normal full pair of blocks of AD
			adlen = ad_encryption(&A, s, k, adlen, CNT, 0x08, n, t);
		}
	}

	reset_lfsr_gf56(CNT);

	n = MSG_BLK_LEN;
	if (d == 0) {
		*clen = mlen + CRYPTO_ABYTES;
	}
	else {
		mlen = mlen - CRYPTO_ABYTES;
		*clen = mlen;
	}

	if (mlen == 0) { // M is an empty string
		lfsr_gf56(CNT);
		nonce_encryption(N, CNT, s, k, t, 0x15);
	}
	else while (mlen > 0) {
		if (mlen < n) { // The last block of M is incomplete
			mlen = msg_encryption(&I, &c, N, CNT, s, k, n, t, 0x15, mlen);
		}
		else if (mlen == n) { // The last block of M is complete
			mlen = msg_encryption(&I, &c, N, CNT, s, k, n, t, 0x14, mlen);
		}
		else { // A normal full message block
			mlen = msg_encryption(&I, &c, N, CNT, s, k, n, t, 0x04, mlen);
		}
	}

	// Tag generation 

	if (d == 1) {
		// Tag verification
		for (i = 0; i < 16; i++) {
			g8A(s, T);
			if (T[i] != (*(I + i))) {
				return -1;
			}
		}
	}
	else {
		generate_tag(&c, s, n, clen);
	}

	return 0;
}

int romulus_t_encrypt(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k
)
{
	unsigned char Z[16];
	unsigned char CNT[7];
	unsigned char CNT_Z[7] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	const unsigned char* A;
	const unsigned char* M;
	const unsigned char* N;
	unsigned long long mlen_int;
	unsigned char LR[32];
	unsigned int i;

	(void)nsec;
	A = ad;
	M = m;
	N = npub;

	reset_lfsr_gf56(CNT);

	kdf(k, Z, N, CNT_Z);
	*clen = mlen + 16;
	mlen_int = mlen;

	while (mlen != 0) {
		mlen = msg_encryptionT(&M, &c, N, CNT, Z, mlen);
	}

	// T = hash(A||N||M)
	// We need to first pad A, N and C
	c = c - mlen_int;
	i = crypto_hash_vector(LR, A, adlen, c, mlen_int, N, CNT);


	//reset_lfsr_gf56(CNT);
	c = c + mlen_int;
	generate_tagT(c, LR, CNT_Z, k);

	return 0;
}

//////////// Romulus Op M & N //////////////

int romulus_m_encrypt_Op(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k) {

	unsigned char s[16];
	unsigned char CNT[8];
	unsigned char T[16];
	const unsigned char* N;
	unsigned char w;
	unsigned long long xlen;

	skinny_ctrl l_skinny_ctrl;
	l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

	(void)nsec;
	N = npub;

	xlen = mlen;

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) = 0;
	*(uint32_t*)(&s[4]) = 0;
	*(uint32_t*)(&s[8]) = 0;
	*(uint32_t*)(&s[12]) = 0;

#else

	s[0] = 0;
	s[1] = 0;
	s[2] = 0;
	s[3] = 0;
	s[4] = 0;
	s[5] = 0;
	s[6] = 0;
	s[7] = 0;
	s[8] = 0;
	s[9] = 0;
	s[10] = 0;
	s[11] = 0;
	s[12] = 0;
	s[13] = 0;
	s[14] = 0;
	s[15] = 0;

#endif

	reset_lfsr_gf56O(CNT);

	w = 48;

	if (adlen == 0) {
		w = w ^ 2;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (32) < 16) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 16) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (32) == 0) {
		w = w ^ 8;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (32) < 16) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 16) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (32) < 16) {
		w = w ^ 2;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (32) < 16) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 16) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else if (adlen % (32) == 16) {
		w = w ^ 0;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (32) < 16) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 16) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}
	else {
		w = w ^ 10;
		if (xlen == 0) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 0) {
			w = w ^ 4;
		}
		else if (xlen % (32) < 16) {
			w = w ^ 1;
		}
		else if (xlen % (32) == 16) {
			w = w ^ 0;
		}
		else {
			w = w ^ 5;
		}
	}

	if (adlen == 0) { // AD is an empty string
		lfsr_gf56O(CNT);
	}
	else while (adlen > 0) {
		adlen = ad_encryptionO(&ad, s, k, adlen, CNT, 40, &l_skinny_ctrl);
	}

	if ((w & 8) == 0) {
		xlen = ad2msg_encryptionO(&m, CNT, s, k, 44, xlen, &l_skinny_ctrl);
	}
	else if (mlen == 0) {
		lfsr_gf56O(CNT);
	}
	while (xlen > 0) {
		xlen = ad_encryptionO(&m, s, k, xlen, CNT, 44, &l_skinny_ctrl);
	}
	nonce_encryptionO(N, CNT, s, k, w, &l_skinny_ctrl);

	// Tag generation
	g8A(s, T);

	m = m - mlen;

	l_skinny_ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

	reset_lfsr_gf56O(CNT);

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) = *(uint32_t*)(&T[0]);
	*(uint32_t*)(&s[4]) = *(uint32_t*)(&T[4]);
	*(uint32_t*)(&s[8]) = *(uint32_t*)(&T[8]);
	*(uint32_t*)(&s[12]) = *(uint32_t*)(&T[12]);

#else

	s[0] = T[0];
	s[1] = T[1];
	s[2] = T[2];
	s[3] = T[3];
	s[4] = T[4];
	s[5] = T[5];
	s[6] = T[6];
	s[7] = T[7];
	s[8] = T[8];
	s[9] = T[9];
	s[10] = T[10];
	s[11] = T[11];
	s[12] = T[12];
	s[13] = T[13];
	s[14] = T[14];
	s[15] = T[15];

#endif

	* clen = mlen + 16;

	if (mlen > 0) {
		nonce_encryptionO(N, CNT, s, k, 36, &l_skinny_ctrl);
		while (mlen > 16) {
			mlen = msg_encryptionO(&m, &c, N, CNT, s, k, 36, mlen, &l_skinny_ctrl);
		}
		rho_ud16(m, c, s, mlen);
		c = c + mlen;
		m = m + mlen;
	}

	// Tag Concatenation
	c[0] = T[0];
	c[1] = T[1];
	c[2] = T[2];
	c[3] = T[3];
	c[4] = T[4];
	c[5] = T[5];
	c[6] = T[6];
	c[7] = T[7];
	c[8] = T[8];
	c[9] = T[9];
	c[10] = T[10];
	c[11] = T[11];
	c[12] = T[12];
	c[13] = T[13];
	c[14] = T[14];
	c[15] = T[15];

	c = c - *clen;

	return 0;

}


int romulus_n_encrypt_Op(
	unsigned char* c, unsigned long long* clen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* ad, unsigned long long adlen,
	const unsigned char* nsec,
	const unsigned char* npub,
	const unsigned char* k) {

	unsigned char s[16];
	unsigned char CNT[8];
	const unsigned char* A;
	const unsigned char* M;
	const unsigned char* N;

	skinny_ctrl ctrl;
	ctrl.func_skinny_128_384_enc = skinny_128_384_enc123_12;

	(void)nsec;
	A = ad;
	M = m;
	N = npub;

#ifdef ___ENABLE_WORD_CAST

	* (uint32_t*)(&s[0]) = 0;
	*(uint32_t*)(&s[4]) = 0;
	*(uint32_t*)(&s[8]) = 0;
	*(uint32_t*)(&s[12]) = 0;

#else

	s[0] = 0;
	s[1] = 0;
	s[2] = 0;
	s[3] = 0;
	s[4] = 0;
	s[5] = 0;
	s[6] = 0;
	s[7] = 0;
	s[8] = 0;
	s[9] = 0;
	s[10] = 0;
	s[11] = 0;
	s[12] = 0;
	s[13] = 0;
	s[14] = 0;
	s[15] = 0;

#endif

	reset_lfsr_gf56O(CNT);

	if (adlen == 0) { // AD is an empty string
		lfsr_gf56O(CNT);
		nonce_encryptionO(N, CNT, s, k, 0x1a, &ctrl);
	}
	else while (adlen > 0) {
		if (adlen < 16) { // The last block of AD is odd and incomplete
			adlen = ad_encryption_ud16(&A, s, adlen, CNT);
			nonce_encryptionO(N, CNT, s, k, 0x1a, &ctrl);
		}
		else if (adlen == 16) { // The last block of AD is odd and complete
			adlen = ad_encryption_eq16(&A, s, CNT);
			nonce_encryptionO(N, CNT, s, k, 0x18, &ctrl);
		}
		else if (adlen < 32) { // The last block of AD is even and incomplete
			adlen = ad_encryption_ov16(&A, s, k, adlen, CNT, 0x08, &ctrl);
			nonce_encryptionO(N, CNT, s, k, 0x1a, &ctrl);
		}
		else if (adlen == 32) { // The last block of AD is even and complete
			adlen = ad_encryption_eqov32(&A, s, k, adlen, CNT, 0x08, &ctrl);
			nonce_encryptionO(N, CNT, s, k, 0x18, &ctrl);
		}
		else { // A normal full pair of blocks of AD
			adlen = ad_encryption_eqov32(&A, s, k, adlen, CNT, 0x08, &ctrl);
		}
	}

	ctrl.func_skinny_128_384_enc = skinny_128_384_enc1_1;

	reset_lfsr_gf56O(CNT);

	*clen = mlen + 16;

	if (mlen == 0) { // M is an empty string
		lfsr_gf56O(CNT);
		nonce_encryptionO(N, CNT, s, k, 0x15, &ctrl);
	}
	else while (mlen > 0) {
		if (mlen < 16) { // The last block of M is incomplete
			mlen = msg_encryption_ud16(&M, &c, N, CNT, s, k, 0x15, mlen, &ctrl);
		}
		else if (mlen == 16) { // The last block of M is complete
			mlen = msg_encryption_eqov16(&M, &c, N, CNT, s, k, 0x14, mlen, &ctrl);
		}
		else { // A normal full message block
			mlen = msg_encryption_eqov16(&M, &c, N, CNT, s, k, 0x04, mlen, &ctrl);
		}
	}

	// Tag generation
	generate_tagO(&c, s, clen);

	return 0;
}