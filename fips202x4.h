//
// This is the interface to the 4x SHAKE-256 implementation; it XOF's 4
// different (same length) inputs at once, and then generates 4 different
// streams
//
// It wouldn't be that difficult to define a class hierarchy, where the
// subclasses are the variious SHA-3/XOR types (SHA3-256 vs SHA3-512 vs
// SHAKE-128 vs SHAKE-256)
// However, since this project needs only SHAKE-256, I haven't bothered
//
#if !defined(FIPS202X4_H_)
#define FIPS202X4_H_

#include <immintrin.h>
#include "api.h"

namespace slh_dsa {

typedef struct SHAKE256_4X_CTX {
    union {
        uint64_t s[25][4];
        __m256i state[25];
    };
    unsigned index;
} SHAKE256_4X_CTX;

void shake256_4x_inc_init(SHAKE256_4X_CTX* ctx);
void shake256_4x_inc_absorb(SHAKE256_4X_CTX* ctx,
                            const uint8_t *input0,
                            const uint8_t *input1,
                            const uint8_t *input2,
                            const uint8_t *input3,
                            size_t inlen);
void shake256_4x_inc_finalize(SHAKE256_4X_CTX* ctx);
void shake256_4x_inc_squeeze(uint8_t *output0,
                            uint8_t *output1,
                            uint8_t *output2,
                            uint8_t *output3,
                            size_t outlen, SHAKE256_4X_CTX* ctx);

} /* namespace slh_dsa */

#endif /* FIPS202X4_H_ */
