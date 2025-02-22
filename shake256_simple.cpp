/*
 * This file has support for the low level SHAKE-256-simple routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "fips202.h"
#include "fips202x4.h"

namespace slh_dsa {

/**
 * The SHAKE version of thash
 */
void key_shake::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned n = len_hash();
    SHAKE256_CTX ctx;

    shake256_inc_init_from_precompute(&ctx, &pre_pub_seed );
    shake256_inc_absorb(&ctx, addr, addr_bytes);
    shake256_inc_absorb(&ctx, in, inblocks * n);
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, n, &ctx);
}

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void key_shake::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx4)
{
    unsigned n = len_hash();
    SHAKE256_4X_CTX ctx;

    shake256_4x_inc_init_from_precompute(&ctx, &pre_pub_seed );
    shake256_4x_inc_absorb(&ctx,
		    addrx4[0],
		    addrx4[1],
		    addrx4[2],
		    addrx4[3],
		    addr_bytes);
    shake256_4x_inc_absorb(&ctx, in[0], in[1], in[2], in[3], inblocks * n);
    shake256_4x_inc_finalize(&ctx);
    shake256_4x_inc_squeeze(out[0], out[1], out[2], out[3], n, &ctx);
}

} /* slh_dsa */
