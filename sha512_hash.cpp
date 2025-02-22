/*
 * This file has support for the L3, L5 SHA-256-based parameter sets
 * These parameter sets use SHA-512 to do the initial message hashes
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha512.h"
#include "mgf1.h"

namespace slh_dsa {

// prf_msg is defined as HMAC( prf, opt_rand || msg )
void key_sha2_L35::prf_msg( unsigned char *result,
		              const unsigned char *opt_rand,
                              unsigned char domain_separator_byte,
                              const void *context, size_t len_context,
                              const void *oid, size_t len_oid,
			      const unsigned char *msg, size_t len_msg ) {
    SHA512_CTX ctx;
    unsigned char block[sha512_block_size];
    unsigned char hash_output[sha512_output_size];
    size_t n = len_hash();
    const unsigned char* prf = get_prf();

    // Do the inner hash
    ctx.init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x36 ^ prf[i];
    }
    memset( &block[n], 0x36, sha512_block_size-n );
    ctx.update( block, sha512_block_size );
    ctx.update( opt_rand, n );
    ctx.update( &domain_separator_byte, 1 );
    unsigned char c = len_context;
    ctx.update( &c, 1 );
    if (context) ctx.update( context, len_context );
    if (oid) ctx.update( oid, len_oid );
    ctx.update( msg, len_msg );

    ctx.final(hash_output);

    // Do the outer hash
    ctx.init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x5c ^ prf[i];
    }
    memset( &block[n], 0x5c, sha512_block_size-n );
    ctx.update( block, sha512_block_size );
    ctx.update( hash_output, sha512_output_size );
    ctx.final( hash_output );

    memcpy( result, hash_output, n );

    zeroize( block, sizeof block );  // prf is supposed to be secret
    ctx.zeroize();
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void key_sha2_L35::h_msg( unsigned char *result, size_t len_result,
		              const unsigned char *r,
                              unsigned char domain_separator_byte,
                              const void *context, size_t len_context,
                              const void *oid, size_t len_oid,
			      const void *msg, size_t len_msg ) {
    unsigned char msg_hash[ sha512_output_size  + 2*max_len_hash ];
    size_t n = len_hash();

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    SHA512_CTX ctx;
    ctx.init();
    ctx.update(r, n);
    ctx.update(pk_seed, n);
    ctx.update(pk_root, n);
    ctx.update( &domain_separator_byte, 1 );
    unsigned char c = len_context;
    ctx.update( &c, 1 );
    if (context) ctx.update( context, len_context );
    if (oid) ctx.update( oid, len_oid );
    ctx.update(msg, len_msg);
    ctx.final(msg_hash + 2*n);

    // Now do the outer MGF1
    memcpy( msg_hash,   r,       n );
    memcpy( msg_hash+n, pk_seed, n );
    mgf1<SHA512_CTX> stream( msg_hash, 2*n + sha512_output_size );
    stream.output( result, len_result );
}

} /* namespace slh_dsa */
