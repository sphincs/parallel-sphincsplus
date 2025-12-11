#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha512avx512.h"
#include "sha512.h"   /* For SHA512_RC */

namespace slh_dsa {

typedef uint64_t u64;
typedef __m512i u512;

#define ROTR32(x, y) _mm512_rol_epi32(x, 32-y)
#define ROTL32(x, y) _mm512_rol_epi32(x, y)

#define ROTL64(x, y) _mm512_rol_epi64(x, y)

static const int AT = 0xf0;        // Selection masks for the ternary logic instruction
static const int BT = 0xcc;
static const int CT = 0xaa;

static void TRANSPOSE_AND_BYTESWAP( u512 m[16], const unsigned char *in ) {

    // Read in the input and byteswap
    u512 byteswap_c = _mm512_set1_epi64(0x00ff00ff00ff00ff);
    for (unsigned i=0; i<16; i++) {
        u512 t  = _mm512_loadu_si512((__m512i *)( &in[64*i] ));

        /* byteswap t */
        u512 rs = ROTR32( t, 8 );
        u512 ls = ROTL32( t, 8 );
        t = _mm512_ternarylogic_epi64(byteswap_c,rs,ls,(~AT&BT) | (AT&CT));

        t = ROTL64( t, 32 );

        m[i] = t;
    }

    // Now, transpose the 64 bit elements
    u512 c = _mm512_set_epi64(
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
    u512 z[16];
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~3);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v23016745 );
        u512 u = m[j+4];
        u512 ur = __builtin_shuffle(u, v23016745 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        z[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        z[j+4] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<8; i++) {
        u512 t = z[i];
        u512 tr = __builtin_shuffle(t, v45670123 );
        u512 u = z[i+8];
        u512 ur = __builtin_shuffle(u, v45670123 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        int j = ((i&1) << 3) | (i>>1);  // The words need a bit of shuffling
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+4] = u;
    }
}

static void UNTRANSPOSE_AND_BYTESWAP( unsigned char **out, u512 m[8] ) {
    u512 c = _mm512_set_epi64(
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff);
    __v8di v10325476 = { 1, 0, 3, 2, 5, 4, 7, 6 };
    for (unsigned i=0; i<8; i+=2) {
        u512 t = m[i];
        u512 tr = __builtin_shuffle(t, v10325476);
        u512 u = m[i+1];
        u512 ur = __builtin_shuffle(u, v10325476);
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[i+1] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v23016745 = { 2, 3, 0, 1, 6, 7, 4, 5 };
    for (unsigned i=0; i<4; i++) {
        int j = i + (i&2);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v23016745);
        u512 u = m[j+2];
        u512 ur = __builtin_shuffle(u, v23016745);
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+2] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<4; i++) {
        u512 t = m[i];
        u512 tr = __builtin_shuffle(t, v45670123);
        u512 u = m[i+4];
        u512 ur = __builtin_shuffle(u, v45670123);
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[i] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[i+4] = u;
    }

    u512 byteswap_c = _mm512_set_epi64(
        0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff,
        0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff,
        0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff,
        0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff);
    for (unsigned i=0; i<8; i++) {
        u512 t = m[i];

        /* byteswap t */
        u512 rs = ROTR32( t, 8 );
        u512 ls = ROTL32( t, 8 );
        t = _mm512_ternarylogic_epi64(byteswap_c,rs,ls,(~AT&BT) | (AT&CT));
        t = ROTL64( t, 32 );

        /* and store the result */
        _mm512_storeu_si512(out[i], t);
    }
}

SHA512_8x_CTX::SHA512_8x_CTX(uint64_t *in, unsigned num_blocks) {
    for (size_t i = 0; i < 8; i++) {
        uint64_t t = in[i];
        s[i] = _mm512_set1_epi64(t);
    }

    datalen = 0;
    msglen = 1024 * num_blocks; // Each block is 1024 bits
}

SHA512_8x_CTX::SHA512_8x_CTX(void) {
#define SET8(x) _mm512_set1_epi64(x)
    s[0] = SET8(0x6a09e667f3bcc908ULL);
    s[1] = SET8(0xbb67ae8584caa73bULL);
    s[2] = SET8(0x3c6ef372fe94f82bULL);
    s[3] = SET8(0xa54ff53a5f1d36f1ULL);
    s[4] = SET8(0x510e527fade682d1ULL);
    s[5] = SET8(0x9b05688c2b3e6c1fULL);
    s[6] = SET8(0x1f83d9abfb41bd6bULL);
    s[7] = SET8(0x5be0cd19137e2179ULL);
#undef SET8
    
    datalen = 0;
    msglen = 0;
}

void SHA512_8x_CTX::update( unsigned char **input,
                     unsigned long long len) 
{
    unsigned long long i = 0;

    while (i < len) {
        int bytes_to_copy = len - i;
        if (bytes_to_copy + datalen > 128) bytes_to_copy = 128 - datalen;
        for (int j=0; j<8; j++) {
            memcpy(&msgblocks[128*j+datalen], &input[j][i], bytes_to_copy);
        }
        datalen += bytes_to_copy;
        i += bytes_to_copy;
        if (datalen == 128) {
            transform(msgblocks);
            msglen += 1024;
            datalen = 0;
        }
    }
}

void SHA512_8x_CTX::final(unsigned char **out) {
    unsigned int i, curlen;

    // Padding
    if (datalen < 112) {
        for (i = 0; i < 8; ++i) {
            curlen = datalen;
            msgblocks[128*i + curlen++] = 0x80;
            while(curlen < 128) {
                msgblocks[128*i + curlen++] = 0x00;
            }
        }
    } else {
        for (i = 0; i < 8; ++i) {
            curlen = datalen;
            msgblocks[128*i + curlen++] = 0x80;
            while(curlen < 128) {
                msgblocks[128*i + curlen++] = 0x00;
            }
        }
        transform(msgblocks);
        memset(msgblocks, 0, 8 * 128);
    }

    // Add length of the message to each block
    msglen += datalen * 8;
    for (i = 0; i < 8; i++) {
        msgblocks[128*i + 127] = msglen;
        msgblocks[128*i + 126] = msglen >> 8;
        msgblocks[128*i + 125] = msglen >> 16;
        msgblocks[128*i + 124] = msglen >> 24;
        msgblocks[128*i + 123] = msglen >> 32;
        msgblocks[128*i + 122] = msglen >> 40;
        msgblocks[128*i + 121] = msglen >> 48;
        msgblocks[128*i + 120] = msglen >> 56;
	memset( &msgblocks[128*i + 112], 0, 8 );
    }

    transform(msgblocks);

    // Put the words back into the expected order and deposit them onto the 
    // output
    UNTRANSPOSE_AND_BYTESWAP( out, s );
}

static u512 ADD64( u512 a, u512 b ) {
    return _mm512_add_epi64(a, b);
}

static u512 ROTR64( u512 a, int r ) {
    return _mm512_ror_epi64(a, r);
}

static u512 SHIFTR64( u512 a, int r ) {
    return _mm512_srli_epi64(a, r);
}

static u512 XOR3(u512 a, u512 b, u512 c) {
    return _mm512_ternarylogic_epi64(a,b,c,AT^BT^CT);
}

static u512 ADD4_64(u512 a, u512 b, u512 c, u512 d) {
    return ADD64(ADD64(a, b), ADD64(c, d));
}
static u512 ADD5_64(u512 a, u512 b, u512 c, u512 d, u512 e) {
    return ADD64(a, ADD4_64(b, c, d, e));
}

static u512 MAJ_AVX(u512 a, u512 b, u512 c) {
    return _mm512_ternarylogic_epi64(a,b,c,(AT&BT)|(AT&CT)|(BT&CT));
}
static u512 CH_AVX(u512 a, u512 b, u512 c) {
    return _mm512_ternarylogic_epi64(a,b,c,CT^(AT&(BT^CT))); } // CT^(AT&(BT^CT)) is the choose function
static u512 SIGMA0_AVX(u512 x) {
    return XOR3(ROTR64(x, 28), ROTR64(x, 34), ROTR64(x, 39));
}
static u512 SIGMA1_AVX(u512 x) {
    return XOR3(ROTR64(x, 14), ROTR64(x, 18), ROTR64(x, 41));
}
static u512 GAMMA0_AVX(u512 x) {
    return XOR3(ROTR64(x, 1),  ROTR64(x, 8), SHIFTR64(x, 7));
}
static u512 GAMMA1_AVX(u512 x) {
    return XOR3(ROTR64(x, 19), ROTR64(x, 61), SHIFTR64(x, 6));
}

#define SHA512ROUND_AVX(a, b, c, d, e, f, g, h, rc, w) \
    T0 = ADD5_64(h, w, SIGMA1_AVX(e), CH_AVX(e, f, g), _mm512_set1_epi64(SHA512_RC[rc])); \
    T1 = ADD64(SIGMA0_AVX(a), MAJ_AVX(a, b, c)); \
    d = ADD64(d, T0); \
    h = ADD64(T0, T1);

void SHA512_8x_CTX::transform(const unsigned char *data) {
    u512 s0, s1, s2, s3, s4, s5, s6, s7, w[16], T0, T1, nw;

    TRANSPOSE_AND_BYTESWAP( w, data );

    // Initial State
    s0 = s[0];
    s1 = s[1];
    s2 = s[2];
    s3 = s[3];
    s4 = s[4];
    s5 = s[5];
    s6 = s[6];
    s7 = s[7];

    // The first 16 rounds (where the w inputs are directly from the data)
    SHA512ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 0, w[0]);
    SHA512ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 1, w[1]);
    SHA512ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 2, w[2]);
    SHA512ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 3, w[3]);
    SHA512ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 4, w[4]);
    SHA512ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 5, w[5]);
    SHA512ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 6, w[6]);
    SHA512ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 7, w[7]);
    SHA512ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, 8, w[8]);
    SHA512ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, 9, w[9]);
    SHA512ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, 10, w[10]);
    SHA512ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, 11, w[11]);
    SHA512ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, 12, w[12]);
    SHA512ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, 13, w[13]);
    SHA512ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, 14, w[14]);
    SHA512ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, 15, w[15]);

#define M(i) (((i)+16) & 0xf)
#define NextW(i) \
    w[M(i)] = ADD4_64(GAMMA1_AVX(w[M((i)-2)]), w[M((i)-7)], GAMMA0_AVX(w[M((i)-15)]), w[M((i)-16)]);

    // The remaining 64 rounds (where the w inputs are a linear fix of the data)
    for (unsigned i = 16; i<80; i+=16) {
    nw = NextW(0+0);
    SHA512ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, i+0, nw);
    nw = NextW(0+1);
    SHA512ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, i+1, nw);
    nw = NextW(0+2);
    SHA512ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, i+2, nw);
    nw = NextW(0+3);
    SHA512ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, i+3, nw);
    nw = NextW(0+4);
    SHA512ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, i+4, nw);
    nw = NextW(0+5);
    SHA512ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, i+5, nw);
    nw = NextW(0+6);
    SHA512ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, i+6, nw);
    nw = NextW(0+7);
    SHA512ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, i+7, nw);

    nw = NextW(8+0);
    SHA512ROUND_AVX(s0, s1, s2, s3, s4, s5, s6, s7, i+8, nw);
    nw = NextW(8+1);
    SHA512ROUND_AVX(s7, s0, s1, s2, s3, s4, s5, s6, i+9, nw);
    nw = NextW(8+2);
    SHA512ROUND_AVX(s6, s7, s0, s1, s2, s3, s4, s5, i+10, nw);
    nw = NextW(8+3);
    SHA512ROUND_AVX(s5, s6, s7, s0, s1, s2, s3, s4, i+11, nw);
    nw = NextW(8+4);
    SHA512ROUND_AVX(s4, s5, s6, s7, s0, s1, s2, s3, i+12, nw);
    nw = NextW(8+5);
    SHA512ROUND_AVX(s3, s4, s5, s6, s7, s0, s1, s2, i+13, nw);
    nw = NextW(8+6);
    SHA512ROUND_AVX(s2, s3, s4, s5, s6, s7, s0, s1, i+14, nw);
    nw = NextW(8+7);
    SHA512ROUND_AVX(s1, s2, s3, s4, s5, s6, s7, s0, i+15, nw);
    }

    // Feed Forward
    s[0] = ADD64(s0, s[0]);
    s[1] = ADD64(s1, s[1]);
    s[2] = ADD64(s2, s[2]);
    s[3] = ADD64(s3, s[3]);
    s[4] = ADD64(s4, s[4]);
    s[5] = ADD64(s5, s[5]);
    s[6] = ADD64(s6, s[6]);
    s[7] = ADD64(s7, s[7]);
}

} /* namespace slh_dsa */
