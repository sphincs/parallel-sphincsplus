/*
 * This file has support for the low level SHAKE-robust routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "fips202.h"
#include "fips202x4.h"

namespace sphincs_plus {

/**
 * The robust version of thash
 */
void key_shake_robust::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned n = len_hash();
    SHAKE256_CTX mask_ctx;
    SHAKE256_CTX ctx;

    shake256_inc_init_from_precompute(&mask_ctx, &pre_pub_seed );
    shake256_inc_absorb(&mask_ctx, addr, addr_bytes);
    shake256_inc_finalize(&mask_ctx);

    shake256_inc_init_from_precompute(&ctx, &pre_pub_seed );
    shake256_inc_absorb(&ctx, addr, addr_bytes);
    for (unsigned i=0; i<inblocks; i++) {
        unsigned char m_plus[max_len_hash];
        shake256_inc_squeeze(m_plus, n, &mask_ctx);
	for (unsigned j=0; j<n; j++) {
	    m_plus[j] ^= *in++;
	}
        shake256_inc_absorb(&ctx, m_plus, n);
    }
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, n, &ctx);
}

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 *
 * Idea of the future: it might be faster to generate a precomputed
 * mask for both ctx and mask_ctx, and initialize both with it...
 */
void key_shake_robust::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx4)
{
    unsigned n = len_hash();
    SHAKE256_4X_CTX mask_ctx;
    SHAKE256_4X_CTX ctx;

    shake256_4x_inc_init_from_precompute(&mask_ctx, &pre_pub_seed );
    shake256_4x_inc_absorb(&mask_ctx,
		    addrx4[0],
		    addrx4[1],
		    addrx4[2],
		    addrx4[3],
		    addr_bytes);
    shake256_4x_inc_finalize(&mask_ctx);

    shake256_4x_inc_init_from_precompute(&ctx, &pre_pub_seed );
    shake256_4x_inc_absorb(&ctx,
		    addrx4[0],
		    addrx4[1],
		    addrx4[2],
		    addrx4[3],
		    addr_bytes);
    for (unsigned i=0, t=0; i<inblocks; i++, t+=n) {
        unsigned char m_plus[4][max_len_hash];
        shake256_4x_inc_squeeze(m_plus[0],
                                m_plus[1],
                                m_plus[2],
                                m_plus[3], n, &mask_ctx);

	for (int m=0; m<4; m++) {
            for (unsigned j=0; j<n; j++) {
	         m_plus[m][j] ^= in[m][j+t];
           }
	}
        shake256_4x_inc_absorb(&ctx, m_plus[0],
                                     m_plus[1],
                                     m_plus[2],
                                     m_plus[3], n);
    }
    shake256_4x_inc_finalize(&ctx);
    shake256_4x_inc_squeeze(out[0], out[1], out[2], out[3], n, &ctx);
}

} /* sphincs_plus */
