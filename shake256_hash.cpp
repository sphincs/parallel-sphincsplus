/*
 * This file has support for SHAKE-256-based parameter sets
 * This does those functions that are the same for both simple and
 * robust parameter sets
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "fips202.h"
#include "fips202x4.h"

namespace slh_dsa {

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 * This is SHAKE-256 specific
 */
void key_shake::prf_addr_xn(unsigned char **out,
                const addr_t* addrx4)
{
    SHAKE256_4X_CTX ctx;
    unsigned n = len_hash();

    shake256_4x_inc_init_from_precompute(&ctx, &pre_pub_seed );
    shake256_4x_inc_absorb(&ctx,
                           addrx4[0],
                           addrx4[1],
                           addrx4[2],
                           addrx4[3],
                           addr_bytes);
    const unsigned char *secret_seed = get_secret_seed();
    shake256_4x_inc_absorb(&ctx,
		           secret_seed,
		           secret_seed,
		           secret_seed,
		           secret_seed,
                           n);
    shake256_4x_inc_finalize(&ctx);
    shake256_4x_inc_squeeze(out[0], out[1], out[2], out[3],
                            n, &ctx);
}

// prf_msg is defined as SHAKE256( prf || optrand || msg )
void key_shake::prf_msg( unsigned char *result,
              const unsigned char *opt_rand,
              unsigned char domain_separator_byte,
              const void *context, size_t len_context,
              const void *oid, size_t len_oid,
              const unsigned char *msg, size_t len_msg ) {
    SHAKE256_CTX ctx;
    unsigned n = len_hash();

    shake256_inc_init(&ctx);

    shake256_inc_absorb(&ctx, get_prf(), n);
    shake256_inc_absorb(&ctx, opt_rand, n);
    shake256_inc_absorb(&ctx, &domain_separator_byte, 1 );
    unsigned char c = len_context;
    shake256_inc_absorb(&ctx, &c, 1 );
    if (context) shake256_inc_absorb(&ctx, static_cast<const unsigned char*>(context), len_context );
    if (oid) shake256_inc_absorb(&ctx, static_cast<const unsigned char*>(oid), len_oid );
    shake256_inc_absorb(&ctx, msg, len_msg);

    shake256_inc_finalize(&ctx);

    shake256_inc_squeeze(result, n, &ctx);
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void key_shake::h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              unsigned char domain_separator_byte,
              const void *context, size_t len_context,
              const void *oid, size_t len_oid,
              const void *msg, size_t len_msg ) {
    SHAKE256_CTX ctx;
    unsigned n = len_hash();

    shake256_inc_init(&ctx);

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    shake256_inc_absorb(&ctx, r, n);
    shake256_inc_absorb(&ctx, pk_seed, n);
    shake256_inc_absorb(&ctx, pk_root, n);
    shake256_inc_absorb(&ctx, &domain_separator_byte, 1 );
    unsigned char c = len_context;
    shake256_inc_absorb(&ctx, &c, 1 );
    if (context) shake256_inc_absorb(&ctx, static_cast<const unsigned char*>(context), len_context );
    if (oid) shake256_inc_absorb(&ctx, static_cast<const unsigned char*>(oid), len_oid );
    shake256_inc_absorb(&ctx, static_cast<const unsigned char*>(msg), len_msg);

    shake256_inc_finalize(&ctx);

    shake256_inc_squeeze(result, len_result, &ctx);
}

//
// Scurry away copies of the public and secret seeds
void key_shake::set_public_key(const unsigned char *public_key) {
    key::set_public_key(public_key);
    shake256_precompute( &pre_pub_seed, get_public_seed(), len_hash() );
}

void key_shake::set_private_key(const unsigned char *private_key) {
    key::set_private_key(private_key);
    shake256_precompute( &pre_pub_seed, get_public_seed(), len_hash() );
}

unsigned key_shake::num_track(void) {
    return 4;
}
unsigned key_shake::num_log_track(void) {
    return 2;
}

} /* namespace slh_dsa */
