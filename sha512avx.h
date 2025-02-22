#ifndef SHA512AVX_H
#define SHA512AVX_H
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

typedef struct SHA512state4x {
    __m256i s[8];
    unsigned char msgblocks[4*128];
    int datalen;
    unsigned long long msglen;
} sha512ctx4x;


void sha512_init_frombytes_x4(sha512ctx4x *ctx, uint64_t *s, unsigned long long msglen);
void sha512_init4x(sha512ctx4x *ctx);
void sha512_update4x(sha512ctx4x *ctx, 
                     const void *d0,
                     const void *d1,
                     const void *d2,
                     const void *d3,
                     unsigned long long len);
void sha512_final4x(sha512ctx4x *ctx,
                     __m256i out0[2],
                     __m256i out1[2],
                     __m256i out2[2],
                     __m256i out3[2]);

} /* slh_dsa */

#endif
