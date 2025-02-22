#if !defined(FIPS202_H_)
#define FIPS202_H_

#include <stddef.h>
#include <stdint.h>
#include "api.h"

namespace slh_dsa {

struct SHAKE256_CTX {
    uint64_t s[26];
};

void shake256_inc_init(SHAKE256_CTX* ctx);
void shake256_inc_init_from_precompute(SHAKE256_CTX* ctx,
                                       const SHAKE256_PRECOMPUTE* pre);
void shake256_inc_absorb(SHAKE256_CTX* ctx, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(SHAKE256_CTX* ctx);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, SHAKE256_CTX* ctx);

void shake256_precompute(SHAKE256_PRECOMPUTE* pre, const uint8_t *input, size_t inlen);

} /* namespace slh_dsa */

#endif
