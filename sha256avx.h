#ifndef SHA256AVX_H
#define SHA256AVX_H
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

#define u32 uint32_t
#define u256 __m256i

#define XOR _mm256_xor_si256
#define OR _mm256_or_si256
#define AND _mm256_and_si256
#define ADD32 _mm256_add_epi32
#define NOT(x) _mm256_xor_si256(x, _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))

#define LOAD(src) _mm256_loadu_si256((__m256i *)(src))
#define STORE(dest,src) _mm256_storeu_si256((__m256i *)(dest),src)

#define BYTESWAP(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(0xc,0xd,0xe,0xf,0x8,0x9,0xa,0xb,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0xc,0xd,0xe,0xf,0x8,0x9,0xa,0xb,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3))

#define SHIFTR32(x, y) _mm256_srli_epi32(x, y)
#define SHIFTL32(x, y) _mm256_slli_epi32(x, y)

#define ROTR32(x, y) OR(SHIFTR32(x, y), SHIFTL32(x, 32 - y))
#define ROTL32(x, y) OR(SHIFTL32(x, y), SHIFTR32(x, 32 - y))

#define XOR3(a, b, c) XOR(XOR(a, b), c)

#define ADD3_32(a, b, c) ADD32(ADD32(a, b), c)
#define ADD4_32(a, b, c, d) ADD32(ADD32(ADD32(a, b), c), d)
#define ADD5_32(a, b, c, d, e) ADD32(ADD32(ADD32(ADD32(a, b), c), d), e)

#define MAJ_AVX(a, b, c) XOR(c, AND(XOR(a, c), XOR(b, c)))
#define CH_AVX(a, b, c) XOR(c, AND(a, XOR(b, c)))

#define SIGMA1_AVX(x) XOR3(ROTR32(x, 6), ROTR32(x, 11), ROTR32(x, 25))
#define SIGMA0_AVX(x) XOR3(ROTR32(x, 2), ROTR32(x, 13), ROTR32(x, 22))

#define WSIGMA1_AVX(x) XOR3(ROTR32(x, 17), ROTR32(x, 19), SHIFTR32(x, 10))
#define WSIGMA0_AVX(x) XOR3(ROTR32(x, 7), ROTR32(x, 18), SHIFTR32(x, 3))

#define SHA256ROUND_AVX(a, b, c, d, e, f, g, h, rc, w) \
    T0 = ADD5_32(h, SIGMA1_AVX(e), CH_AVX(e, f, g), _mm256_set1_epi32(SHA256_RC[rc]), w); \
    d = ADD32(d, T0); \
    T1 = ADD32(SIGMA0_AVX(a), MAJ_AVX(a, b, c)); \
    h = ADD32(T0, T1);

typedef struct SHA256state8x {
    u256 s[8];
    unsigned char msgblocks[8*64];
    int datalen;
    unsigned long long msglen;
} sha256ctx8x;


void sha256_init_frombytes_x8(sha256ctx8x *ctx, uint32_t *s, unsigned long long msglen);
void sha256_init8x(sha256ctx8x *ctx);
void sha256_update8x(sha256ctx8x *ctx, 
                     const void *d0,
                     const void *d1,
                     const void *d2,
                     const void *d3,
                     const void *d4,
                     const void *d5,
                     const void *d6,
                     const void *d7,
                     unsigned long long len);
void sha256_final8x(sha256ctx8x *ctx,
                    u256 *out0,
                    u256 *out1,
                    u256 *out2,
                    u256 *out3,
                    u256 *out4,
                    u256 *out5,
                    u256 *out6,
                    u256 *out7);

void sha256_transform8x(sha256ctx8x *ctx, const unsigned char *data);

} /* namespace slh_dsa */

#endif
