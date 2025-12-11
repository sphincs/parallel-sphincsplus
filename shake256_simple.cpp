/*
 * This file has support for the low level SHAKE-256-simple routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "fips202.h"
#include "fips202x4.h"
#include "shake256avx512.h"

namespace slh_dsa {

/**
 * The SHAKE version of thash
 */
void key_shake::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned n = len_hash();
    SHAKE256_CTX ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, get_public_seed(), n);
    shake256_inc_absorb(&ctx, addr, addr_bytes);
    shake256_inc_absorb(&ctx, in, inblocks * n);
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, n, &ctx);
}

/**
 * 4 or 8-way parallel version of thash; takes 4x or 8x as much input and output
 */
void key_shake::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx)
{
    unsigned n = len_hash();
    const unsigned char *public_seed = get_public_seed();
    if (do_avx512) {
        SHAKE256_8x_CTX ctx;
    
        unsigned char *pointer[8];
        for (int i=0; i<8; i++) {
            pointer[i] = const_cast<unsigned char*>(public_seed);
        }
        ctx.update(pointer, n);
        for (int i=0; i<8; i++) {
            pointer[i] = const_cast<unsigned char*>(addrx[i]);
        }
        ctx.update(pointer, addr_bytes);
        ctx.update(in, inblocks * n);
        ctx.squeeze(out, n);
    } else {
        SHAKE256_4X_CTX ctx;
    
        shake256_4x_inc_init( &ctx );
        shake256_4x_inc_absorb(&ctx,
                        public_seed,
                        public_seed,
                        public_seed,
                        public_seed,
                        n);
        shake256_4x_inc_absorb(&ctx,
    		    addrx[0],
    		    addrx[1],
    		    addrx[2],
    		    addrx[3],
    		    addr_bytes);
        shake256_4x_inc_absorb(&ctx, in[0], in[1], in[2], in[3], inblocks * n);
        shake256_4x_inc_finalize(&ctx);
        shake256_4x_inc_squeeze(out[0], out[1], out[2], out[3], n, &ctx);
    }
}

} /* slh_dsa */
