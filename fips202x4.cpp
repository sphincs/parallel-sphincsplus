#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fips202x4.h"

/*
 * Interface to the underlying Keccak AVX2 implementation
 */
#include "keccak4x/KeccakP-1600-times4-SnP.h"

namespace sphincs_plus {

void shake256_4x_inc_init(SHAKE256_4X_CTX *ctx) {
    memset( ctx->s, 0, sizeof ctx->s );
    ctx->index = 0;
}

const int rate = 136;   // For SHAKE256
void shake256_4x_inc_absorb(SHAKE256_4X_CTX* ctx,
                            const uint8_t *input0,
                            const uint8_t *input1,
                            const uint8_t *input2,
                            const uint8_t *input3,
                            size_t mlen) {
    size_t i;

    unsigned index = ctx->index;
    while (mlen) {
	unsigned num_bytes = rate - index;
	if (num_bytes > mlen) num_bytes = mlen;
	for (i = 0; i < num_bytes; i++) {
	    unsigned byte_offset = (index+i)>>3;
	    unsigned bit_shift = ((index+i)&7)<<3;;
	    ctx->s[byte_offset][0] ^= (uint64_t)input0[i] << bit_shift;
	    ctx->s[byte_offset][1] ^= (uint64_t)input1[i] << bit_shift;
	    ctx->s[byte_offset][2] ^= (uint64_t)input2[i] << bit_shift;
	    ctx->s[byte_offset][3] ^= (uint64_t)input3[i] << bit_shift;
	}
	index += num_bytes;
        mlen -= num_bytes;
        input0 += num_bytes;
        input1 += num_bytes;
        input2 += num_bytes;
        input3 += num_bytes;
	if (index == rate) {
            KeccakP1600times4_PermuteAll_24rounds(ctx->state);
	    index = 0;
	}
    }
    ctx->index = index;
}

void shake256_4x_inc_finalize(SHAKE256_4X_CTX* ctx) {
    unsigned char final_pad[1];
    final_pad[0] = 0x1f;   // 0x1f means "SHAKE256"

    shake256_4x_inc_absorb(ctx,
                           final_pad, final_pad, final_pad, final_pad,
		           1);

    /* Set the MSBit at the end for each track */
    ctx->index = rate-1;
    final_pad[0] = 0x80;
        // This will cause another permutation, and reset index to 0
    shake256_4x_inc_absorb(ctx,
                           final_pad, final_pad, final_pad, final_pad,
		           1);
}

void shake256_4x_inc_squeeze(uint8_t *output0,
                             uint8_t *output1,
                             uint8_t *output2,
                             uint8_t *output3,
                             size_t outlen, SHAKE256_4X_CTX* ctx) {
    unsigned index = ctx->index;

    while (outlen > 0) {
	if (index == rate) {
            KeccakP1600times4_PermuteAll_24rounds(ctx->s);
            index = 0;
	}
	unsigned num_bytes = rate - index;
	if (num_bytes > outlen) num_bytes = outlen;
	for (unsigned i = 0; i < num_bytes; i++) {
	    unsigned word_offset = (index+i)>>3;
	    unsigned bit_shift = ((index+i)&7)<<3;;
	    *output0++ = ctx->s[word_offset][0] >> bit_shift;
	    *output1++ = ctx->s[word_offset][1] >> bit_shift;
	    *output2++ = ctx->s[word_offset][2] >> bit_shift;
	    *output3++ = ctx->s[word_offset][3] >> bit_shift;
	}
	index += num_bytes;
        outlen -= num_bytes;
    }

    ctx->index = index;
}

void shake256_4x_inc_init_from_precompute(SHAKE256_4X_CTX* ctx,
                                       const SHAKE256_PRECOMPUTE* pre) {
    unsigned i;
    unsigned nonzero = pre->nonzero;
    for (i=0; i<nonzero; i++) {
        uint64_t entry = pre->s[i];
	ctx->s[i][0] = entry;
	ctx->s[i][1] = entry;
	ctx->s[i][2] = entry;
	ctx->s[i][3] = entry;
    }
    memset( &ctx->s[nonzero][0], 0, 4*8*(25-nonzero) );

    ctx->index = pre->index;
}

} /* namespace sphincs_plus */

