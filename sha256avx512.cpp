//
// This is the AVX-512 version of SHA-256
// This computes 16 SHA-256's in parallel.  The 16 preimages must be the
// same length, but can otherwise be completely independent
//
#include <string.h>
#include <stdint.h>

#include "sha256avx512.h"

namespace slh_dsa {

typedef __m512i u512;

static const uint32_t RC[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static u512 ADD32( u512 a, u512 b ) { return _mm512_add_epi32( a, b ); }

static u512 SHIFTR32( u512 x, int y) { return _mm512_srli_epi32(x, y); }

static u512 ROTR32( u512 x, int y) { return _mm512_rol_epi32(x, 32-y); }
static u512 ROTL32( u512 x, int y) { return _mm512_rol_epi32(x, y); }

#define AT  _MM_TERNLOG_A   // To reduce typing
#define BT  _MM_TERNLOG_B
#define CT  _MM_TERNLOG_C

static u512 XOR3(u512 a, u512 b, u512 c) { return _mm512_ternarylogic_epi64(a,b,c,AT^BT^CT); }

static u512 ADD4_32(u512 a, u512 b, u512 c, u512 d) { return ADD32(ADD32(a, b), ADD32(c, d) ); }
static u512 ADD5_32(u512 a, u512 b, u512 c, u512 d, u512 e) { return ADD32( ADD4_32(a, b, c, d), e ); }

static u512 MAJ_AVX(u512 a, u512 b, u512 c) { return _mm512_ternarylogic_epi64(a,b,c,(AT&BT)|(AT&CT)|(BT&CT)); }
static u512 CH_AVX(u512 a, u512 b, u512 c) { return _mm512_ternarylogic_epi64(a,b,c,CT^(AT&(BT^CT))); } // CT^(AT&(BT^CT)) is the choose function

static u512 SIGMA1_AVX(u512 x) { return XOR3(ROTR32(x, 6), ROTR32(x, 11), ROTR32(x, 25)); }
static u512 SIGMA0_AVX(u512 x) { return XOR3(ROTR32(x, 2), ROTR32(x, 13), ROTR32(x, 22)); }

static u512 WSIGMA1_AVX(u512 x) { return XOR3(ROTR32(x, 17), ROTR32(x, 19), SHIFTR32(x, 10)); }
static u512 WSIGMA0_AVX(u512 x) { return XOR3(ROTR32(x, 7), ROTR32(x, 18), SHIFTR32(x, 3)); }

#define SHA256ROUND_AVX(a, b, c, d, e, f, g, h, rc, round) \
    T0 = ADD5_32(h, SIGMA1_AVX(e), CH_AVX(e, f, g), _mm512_set1_epi32(RC[rc]), w[round & 15]); \
    d = ADD32(d, T0); \
    T1 = ADD32(SIGMA0_AVX(a), MAJ_AVX(a, b, c)); \
    h = ADD32(T0, T1);


//
// This takes the 16 input data blocks, and convert them into the initial
// 16 w array values, in AVX-512 format (line x is placed into bits 32x to 
// 32x+31 of each u512 value, and in little-endian bit order)
static void byteswap_and_transpose( u512 m[16], const unsigned char *in ) {
    u512 byteswap_c = _mm512_set1_epi64(0x00ff00ff00ff00ff);
    for (unsigned i=0; i<16; i++) {
        u512 t  = _mm512_loadu_si512((__m512i *)( &in[64*i] ));

        /* byteswap t */
        u512 rs = ROTR32( t, 8 );
        u512 ls = ROTL32( t, 8 );
        t = _mm512_ternarylogic_epi64(byteswap_c,rs,ls,(~AT&BT) | (AT&CT));

        m[i] = t;
    }

    u512 c = _mm512_set_epi64(
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000);
    for (unsigned i=0; i<16; i+=2) {
        u512 t = m[i];
        u512 u = m[i+1];
        u512 tr = _mm512_rol_epi64(t, 32);
        u512 ur = _mm512_rol_epi64(u, 32);
        t = _mm512_ternarylogic_epi64(c,t,ur,(AT&CT) | (~AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&CT) | (AT&BT));
        m[i+1] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff);
    __v8di v10325476 = { 1, 0, 3, 2, 5, 4, 7, 6 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~1);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v10325476 );
        u512 u = m[j+2];
        u512 ur = __builtin_shuffle(u, v10325476 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+2] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v23016745 = { 2, 3, 0, 1, 6, 7, 4, 5 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~3);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v23016745 );
        u512 u = m[j+4];
        u512 ur = __builtin_shuffle(u, v23016745 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+4] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<8; i++) {
        u512 t = m[i];
        u512 tr = __builtin_shuffle(t, v45670123 );
        u512 u = m[i+8];
        u512 ur = __builtin_shuffle(u, v45670123 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[i+8] = u;
    }
}

//
// This takes the SHA512 state (in our internal AVX-512 format, that is
// where lane x is held in bits 32x to 32x+31 on all 8 context elements),
// and resorts them into the expected SHA-256 output order (where lane x
// is placed into out[x]), and also byteswaps them (because the AVX-512
// order is little-endian).
// This trashes the m input (which is ok, we don't need it anymore)
static void untranspose_and_byteswap( unsigned char **out, u512 m[8] ) {
    u512 c = _mm512_set_epi64(
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000,
        0xffffffff00000000, 0xffffffff00000000);
    for (unsigned i=0; i<8; i+=2) {
        u512 t = m[i];
        u512 u = m[i+1];
        u512 tr = _mm512_rol_epi64(t, 32);
        u512 ur = _mm512_rol_epi64(u, 32);
        t = _mm512_ternarylogic_epi64(c,t,ur,(AT&CT) | (~AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&CT) | (AT&BT));
        m[i+1] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff);
    __v8di v10325476 = { 1, 0, 3, 2, 5, 4, 7, 6 };
    for (unsigned i=0; i<4; i++) {
        int j = i + (i&2);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v10325476);
        u512 u = m[j+2];
        u512 ur = __builtin_shuffle(u, v10325476);
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+2] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v23016745 = { 2, 3, 0, 1, 6, 7, 4, 5 };
    for (unsigned i=0; i<4; i++) {
        u512 t = m[i];
        u512 tr = __builtin_shuffle(t, v23016745);
        u512 u = m[i+4];
        u512 ur = __builtin_shuffle(u, v23016745);
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[i+4] = u;
    }

    u512 byteswap_c = _mm512_set1_epi64(0x00ff00ff00ff00ff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<8; i++) {
        u512 t = m[i];

        /* byteswap t */
        u512 rs = ROTR32( t, 8 );
        u512 ls = ROTL32( t, 8 );
        t = _mm512_ternarylogic_epi64(byteswap_c,rs,ls,(~AT&BT) | (AT&CT));

        /* and store the lower and upper halves of t separately */
        _mm256_storeu_si256( (__m256i*)out[i], _mm512_castsi512_si256(t) );
        t = __builtin_shuffle(t, v45670123);
        _mm256_storeu_si256( (__m256i*)out[i+8], _mm512_castsi512_si256(t) );
    }
}

SHA256_16x_CTX::SHA256_16x_CTX(uint32_t *in, unsigned long long mlen) {

    for (size_t i = 0; i < 8; i++) {
        uint64_t t = in[i] * 0x100000001;
        s[i] = _mm512_set1_epi64(t);
    }

    datalen = 0;
    msglen = mlen;
}

SHA256_16x_CTX::SHA256_16x_CTX(void) {
#define INIT( index, value ) \
    { uint64_t v = (value * (uint64_t)0x100000001); \
      s[index] = _mm512_set1_epi64( v ); \
    }
    INIT(0, 0x6a09e667);
    INIT(1, 0xbb67ae85);
    INIT(2, 0x3c6ef372);
    INIT(3, 0xa54ff53a);
    INIT(4, 0x510e527f);
    INIT(5, 0x9b05688c);
    INIT(6, 0x1f83d9ab);
    INIT(7, 0x5be0cd19);
#undef INIT
    
    datalen = 0;
    msglen = 0;
}

void SHA256_16x_CTX::update(
                     unsigned char *input[16],
                     unsigned long long len) 
{
    unsigned long long i = 0;

    while (i < len) {
        int bytes_to_copy = len - i;
	if (bytes_to_copy + datalen > 64) bytes_to_copy = 64 - datalen;
        for (int j=0; j<16; j++) {
            memcpy(&msgblocks[64*j+datalen], &input[j][i], bytes_to_copy);
        }
        datalen += bytes_to_copy;
        i += bytes_to_copy;
        if (datalen == 64) {
            transform(msgblocks);
            msglen += 512;
            datalen = 0;
        }        
    }
}

void SHA256_16x_CTX::final(unsigned char *out[16]) {
    unsigned int i, curlen;

    // Padding
    if (datalen < 56) {
        for (i = 0; i < 16; ++i) {
            curlen = datalen;
            msgblocks[64*i + curlen++] = 0x80;
            while(curlen < 64) {
                msgblocks[64*i + curlen++] = 0x00;
            }
        }
    } else {
        for (i = 0; i < 16; ++i) {
            curlen = datalen;
            msgblocks[64*i + curlen++] = 0x80;
            while(curlen < 64) {
                msgblocks[64*i + curlen++] = 0x00;
            }
        }
        transform(msgblocks);
        memset(msgblocks, 0, 16 * 64);
    }

    // Add length of the message to each block
    msglen += datalen * 8;
    for (i = 0; i < 16; i++) {
        msgblocks[64*i + 63] = msglen;
        msgblocks[64*i + 62] = msglen >> 8;
        msgblocks[64*i + 61] = msglen >> 16;
        msgblocks[64*i + 60] = msglen >> 24;
        msgblocks[64*i + 59] = msglen >> 32;
        msgblocks[64*i + 58] = msglen >> 40;
        msgblocks[64*i + 57] = msglen >> 48;
        msgblocks[64*i + 56] = msglen >> 56;
    }
    transform(msgblocks);

    // Compute final hash output and store the final hash values
    untranspose_and_byteswap(out, s);
}

void SHA256_16x_CTX::transform(const unsigned char *data) {
    u512 s0, s1, s2, s3, s4, s5, s6, s7, w[16], T0, T1;

    // Convert the 16 data blocks into the initial 16 w values
    byteswap_and_transpose( &w[0], data );

    // Initial State
    s0 = s[0];
    s1 = s[1];
    s2 = s[2];
    s3 = s[3];
    s4 = s[4];
    s5 = s[5];
    s6 = s[6];
    s7 = s[7];

    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 0, 0);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 1, 1);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 2, 2);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 3, 3);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 4, 4);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 5, 5);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 6, 6);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 7, 7);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 8, 8);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 9, 9);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 10, 10);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 11, 11);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 12, 12);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 13, 13);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 14, 14);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 15, 15);   
#define UPDATE_W(x) ( w[x & 15 ] = ADD4_32( WSIGMA1_AVX(w[(x-2)&15]), w[(x-16)&15], w[(x-7)&15], WSIGMA0_AVX(w[(x-15)&15])))
    UPDATE_W(16);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 16, 16);
    UPDATE_W(17);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 17, 17);
    UPDATE_W(18);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 18, 18);
    UPDATE_W(19);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 19, 19);
    UPDATE_W(20);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 20, 20);
    UPDATE_W(21);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 21, 21);
    UPDATE_W(22);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 22, 22);
    UPDATE_W(23);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 23, 23);
    UPDATE_W(24);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 24, 24);
    UPDATE_W(25);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 25, 25);
    UPDATE_W(26);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 26, 26);
    UPDATE_W(27);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 27, 27);
    UPDATE_W(28);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 28, 28);
    UPDATE_W(29);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 29, 29);
    UPDATE_W(30);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 30, 30);
    UPDATE_W(31);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 31, 31);   
    UPDATE_W(32);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 32, 32);
    UPDATE_W(33);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 33, 33);
    UPDATE_W(34);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 34, 34);
    UPDATE_W(35);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 35, 35);
    UPDATE_W(36);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 36, 36);
    UPDATE_W(37);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 37, 37);
    UPDATE_W(38);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 38, 38);
    UPDATE_W(39);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 39, 39);
    UPDATE_W(40);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 40, 40);
    UPDATE_W(41);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 41, 41);
    UPDATE_W(42);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 42, 42);
    UPDATE_W(43);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 43, 43);
    UPDATE_W(44);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 44, 44);
    UPDATE_W(45);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 45, 45);
    UPDATE_W(46);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 46, 46);
    UPDATE_W(47);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 47, 47);
    UPDATE_W(48);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 48, 48);
    UPDATE_W(49);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 49, 49);
    UPDATE_W(50);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 50, 50);
    UPDATE_W(51);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 51, 51);
    UPDATE_W(52);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 52, 52);
    UPDATE_W(53);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 53, 53);
    UPDATE_W(54);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 54, 54);
    UPDATE_W(55);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 55, 55);
    UPDATE_W(56);
    SHA256ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 56, 56);
    UPDATE_W(57);
    SHA256ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 57, 57); 
    UPDATE_W(58);
    SHA256ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 58, 58);   
    UPDATE_W(59);
    SHA256ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 59, 59);
    UPDATE_W(60);
    SHA256ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 60, 60);
    UPDATE_W(61);
    SHA256ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 61, 61);
    UPDATE_W(62);
    SHA256ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 62, 62);
    UPDATE_W(63);
    SHA256ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 63, 63);

    // Feed Forward
    s[0] = ADD32(s0, s[0]);
    s[1] = ADD32(s1, s[1]);
    s[2] = ADD32(s2, s[2]);
    s[3] = ADD32(s3, s[3]);
    s[4] = ADD32(s4, s[4]);
    s[5] = ADD32(s5, s[5]);
    s[6] = ADD32(s6, s[6]);
    s[7] = ADD32(s7, s[7]);
}

} /* namespace slh_dsa */
