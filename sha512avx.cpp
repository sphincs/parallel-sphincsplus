#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha512avx.h"
#include "sha512.h"  /* For SHA512_RC */

namespace slh_dsa {

typedef uint64_t u64;
typedef __m256i u256;

static void sha512_transform4x(sha512ctx4x *ctx, const unsigned char *data);

#define BYTESWAP(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7))
#define STORE(dest,src) _mm256_storeu_si256((__m256i *)(dest),src)

// Transpose 4 vectors containing 64-bit values
// That is, it rearranges the array:
//     A B C D
//     E F G H
//     I J K L
//     M N O P
// into
//     A E I M
//     B F J N
//     C G K O
//     D H L P
// where each letter stands for 64 bits (and lsbits on the left)
static void transpose(u256 s[4]) {
    u256 tmp[4];
    tmp[0] = _mm256_unpacklo_epi64(s[0], s[1]);
    tmp[1] = _mm256_unpackhi_epi64(s[0], s[1]);
    tmp[2] = _mm256_unpacklo_epi64(s[2], s[3]);
    tmp[3] = _mm256_unpackhi_epi64(s[2], s[3]);
    // tmp is in the order of
    //   A E C G
    //   B F D H
    //   I M K O
    //   J N L P
    s[0] = _mm256_permute2x128_si256(tmp[0], tmp[2], 0x20);
    s[1] = _mm256_permute2x128_si256(tmp[1], tmp[3], 0x20);
    s[2] = _mm256_permute2x128_si256(tmp[0], tmp[2], 0x31);
    s[3] = _mm256_permute2x128_si256(tmp[1], tmp[3], 0x31);
}

void sha512_init_frombytes_x4(sha512ctx4x *ctx, uint64_t *s, unsigned long long msglen) {
    uint64_t t;

    for (size_t i = 0; i < 8; i++) {
        t = s[i];
        ctx->s[i] = _mm256_set_epi64x(t, t, t, t);
    }

    ctx->datalen = 0;
    ctx->msglen = msglen;
}

void sha512_init4x(sha512ctx4x *ctx) {
#define SET4(x) _mm256_set_epi64x(x, x, x, x)
    ctx->s[0] = SET4(0x6a09e667f3bcc908ULL);
    ctx->s[1] = SET4(0xbb67ae8584caa73bULL);
    ctx->s[2] = SET4(0x3c6ef372fe94f82bULL);
    ctx->s[3] = SET4(0xa54ff53a5f1d36f1ULL);
    ctx->s[4] = SET4(0x510e527fade682d1ULL);
    ctx->s[5] = SET4(0x9b05688c2b3e6c1fULL);
    ctx->s[6] = SET4(0x1f83d9abfb41bd6bULL);
    ctx->s[7] = SET4(0x5be0cd19137e2179ULL);
#undef SET4
    
    ctx->datalen = 0;
    ctx->msglen = 0;
}

void sha512_update4x(sha512ctx4x *ctx, 
                     const void *i0,
                     const void *i1,
                     const void *i2,
                     const void *i3,
                     unsigned long long len) 
{
    unsigned i = 0;
    const unsigned char *d0 = static_cast<const unsigned char *>(i0);
    const unsigned char *d1 = static_cast<const unsigned char *>(i1);
    const unsigned char *d2 = static_cast<const unsigned char *>(i2);
    const unsigned char *d3 = static_cast<const unsigned char *>(i3);

    unsigned datalen = ctx->datalen;
    while(i < len) {
        unsigned bytes_to_copy = len - i;
	if (bytes_to_copy + datalen > 128) bytes_to_copy = 128 - datalen;
        memcpy(&ctx->msgblocks[128*0+datalen], d0 + i, bytes_to_copy);
        memcpy(&ctx->msgblocks[128*1+datalen], d1 + i, bytes_to_copy);
        memcpy(&ctx->msgblocks[128*2+datalen], d2 + i, bytes_to_copy);
        memcpy(&ctx->msgblocks[128*3+datalen], d3 + i, bytes_to_copy);
        datalen += bytes_to_copy;
        i += bytes_to_copy;
        if (datalen == 128) {
            sha512_transform4x(ctx, ctx->msgblocks);
            ctx->msglen += 1024;
            datalen = 0;
        }        
    }
    ctx->datalen = datalen;
}

void sha512_final4x(sha512ctx4x *ctx,
                    u256 *out0,
                    u256 *out1,
                    u256 *out2,
                    u256 *out3)
{
    unsigned int i, curlen;

    // Padding
    if (ctx->datalen < 112) {
        for (i = 0; i < 4; ++i) {
            curlen = ctx->datalen;
            ctx->msgblocks[128*i + curlen++] = 0x80;
            while(curlen < 128) {
                ctx->msgblocks[128*i + curlen++] = 0x00;
            }
        }
    } else {
        for (i = 0; i < 4; ++i) {
            curlen = ctx->datalen;
            ctx->msgblocks[128*i + curlen++] = 0x80;
            while(curlen < 128) {
                ctx->msgblocks[128*i + curlen++] = 0x00;
            }
        }
        sha512_transform4x(ctx, ctx->msgblocks);
        memset(ctx->msgblocks, 0, 4 * 128);
    }

    // Add length of the message to each block
    ctx->msglen += ctx->datalen * 8;
    for (i = 0; i < 4; i++) {
        ctx->msgblocks[128*i + 127] = ctx->msglen;
        ctx->msgblocks[128*i + 126] = ctx->msglen >> 8;
        ctx->msgblocks[128*i + 125] = ctx->msglen >> 16;
        ctx->msgblocks[128*i + 124] = ctx->msglen >> 24;
        ctx->msgblocks[128*i + 123] = ctx->msglen >> 32;
        ctx->msgblocks[128*i + 122] = ctx->msglen >> 40;
        ctx->msgblocks[128*i + 121] = ctx->msglen >> 48;
        ctx->msgblocks[128*i + 120] = ctx->msglen >> 56;
	memset( &ctx->msgblocks[128*i + 112], 0, 8 );
    }
    sha512_transform4x(ctx, ctx->msgblocks);

    // Compute final hash output
    transpose(ctx->s);
    transpose(ctx->s+4);

    // Store Hash value
    STORE(out0,   BYTESWAP(ctx->s[0]));
    STORE(out0+1, BYTESWAP(ctx->s[4]));
    STORE(out1,   BYTESWAP(ctx->s[1]));
    STORE(out1+1, BYTESWAP(ctx->s[5]));
    STORE(out2,   BYTESWAP(ctx->s[2]));
    STORE(out2+1, BYTESWAP(ctx->s[6]));
    STORE(out3,   BYTESWAP(ctx->s[3]));
    STORE(out3+1, BYTESWAP(ctx->s[7]));
}

#define XOR _mm256_xor_si256
#define OR _mm256_or_si256
#define AND _mm256_and_si256
#define ADD64 _mm256_add_epi64

#define LOAD(src) _mm256_loadu_si256((__m256i *)(src))

#define SHIFTR64(x, y) _mm256_srli_epi64(x, y)
#define SHIFTL64(x, y) _mm256_slli_epi64(x, y)

#define ROTR64(x, y) OR(SHIFTR64(x, y), SHIFTL64(x, 64 - y))

static u256 XOR3(u256 a, u256 b, u256 c) {
    return XOR(XOR(a, b), c);
}

#define ADD3_64(a, b, c) ADD64(ADD64(a, b), c)
#define ADD4_64(a, b, c, d) ADD64(ADD64(ADD64(a, b), c), d)
#define ADD5_64(a, b, c, d, e) ADD64(ADD64(ADD64(ADD64(a, b), c), d), e)

static u256 MAJ_AVX(u256 a, u256 b, u256 c) {
    return XOR(c, AND(XOR(a, c), XOR(b, c)));
}
static u256 CH_AVX(u256 a, u256 b, u256 c) {
    return XOR(c, AND(a, XOR(b, c)));
}
static u256 SIGMA0_AVX(u256 x) {
    return XOR3(ROTR64(x, 28), ROTR64(x, 34), ROTR64(x, 39));
}
static u256 SIGMA1_AVX(u256 x) {
    return XOR3(ROTR64(x, 14), ROTR64(x, 18), ROTR64(x, 41));
}
static u256 GAMMA0_AVX(u256 x) {
    return XOR3(ROTR64(x, 1),  ROTR64(x, 8), SHIFTR64(x, 7));
}
static u256 GAMMA1_AVX(u256 x) {
    return XOR3(ROTR64(x, 19), ROTR64(x, 61), SHIFTR64(x, 6));
}

#define SHA512ROUND_AVX(a, b, c, d, e, f, g, h, rc, w) \
    T0 = ADD5_64(h, w, SIGMA1_AVX(e), CH_AVX(e, f, g), _mm256_set1_epi64x(SHA512_RC[rc])); \
    T1 = ADD64(SIGMA0_AVX(a), MAJ_AVX(a, b, c)); \
    d = ADD64(d, T0); \
    h = ADD64(T0, T1);

static void sha512_transform4x(sha512ctx4x *ctx, const unsigned char *data) {
    u256 s0, s1, s2, s3, s4, s5, s6, s7, w[16], T0, T1, nw;
    int i;

    // Load words and transform data correctly
    for(i = 0; i < 4; i++) {
        w[i     ] = BYTESWAP(LOAD(data      + 128*i));
        w[i +  4] = BYTESWAP(LOAD(data + 32 + 128*i));
        w[i +  8] = BYTESWAP(LOAD(data + 64 + 128*i));
        w[i + 12] = BYTESWAP(LOAD(data + 96 + 128*i));
    }

    transpose(w);
    transpose(w + 4);
    transpose(w + 8);
    transpose(w + 12);

    // Initial State
    s0 = ctx->s[0];
    s1 = ctx->s[1];
    s2 = ctx->s[2];
    s3 = ctx->s[3];
    s4 = ctx->s[4];
    s5 = ctx->s[5];
    s6 = ctx->s[6];
    s7 = ctx->s[7];

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
    ctx->s[0] = ADD64(s0, ctx->s[0]);
    ctx->s[1] = ADD64(s1, ctx->s[1]);
    ctx->s[2] = ADD64(s2, ctx->s[2]);
    ctx->s[3] = ADD64(s3, ctx->s[3]);
    ctx->s[4] = ADD64(s4, ctx->s[4]);
    ctx->s[5] = ADD64(s5, ctx->s[5]);
    ctx->s[6] = ADD64(s6, ctx->s[6]);
    ctx->s[7] = ADD64(s7, ctx->s[7]);
}

} /* namespace slh_dsa */
