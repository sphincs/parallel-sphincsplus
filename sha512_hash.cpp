/*
 * This file has support for the L5 SHA-256-based parameter sets
 * These parameter sets use SHA-512 to do the initial message hashes
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha512.h"
#include "mgf1.h"

namespace sphincs_plus {

// For the SHA256-L5 parameter sets, redirect the PRF_msg to the version
// that uses SHA-512
void key_sha256_L5_simple::prf_msg( unsigned char *result,
		              const unsigned char *opt,
			      const unsigned char *msg, size_t len_msg ) {
    prf_msg_512(result, opt, msg, len_msg);
}
void key_sha256_L5_robust::prf_msg( unsigned char *result,
		              const unsigned char *opt,
			      const unsigned char *msg, size_t len_msg ) {
    prf_msg_512(result, opt, msg, len_msg);
}

// prf_msg is defined as HMAC( prf, opt_rand || msg )
void sha256_hash::prf_msg_512( unsigned char *result,
              const unsigned char *opt_rand,
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

// For the SHA256-L5 parameter sets, redirect the h_msg to the version
// that uses SHA-512
void key_sha256_L5_simple::h_msg( unsigned char *result, size_t len_result,
		              const unsigned char *r,
			      const unsigned char *msg, size_t len_msg ) {
    h_msg_512(result, len_result, r, msg, len_msg);
}
void key_sha256_L5_robust::h_msg( unsigned char *result, size_t len_result,
		              const unsigned char *r,
			      const unsigned char *msg, size_t len_msg ) {
    h_msg_512(result, len_result, r, msg, len_msg);
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void sha256_hash::h_msg_512( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) {
    unsigned char msg_hash[ sha512_output_size  + 2*max_len_hash ];
    size_t n = len_hash();

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    SHA512_CTX ctx;
    ctx.init();
    ctx.update(r, n);
    ctx.update(pk_seed, n);
    ctx.update(pk_root, n);
    ctx.update(msg, len_msg);
    ctx.final(msg_hash + 2*n);

    // Now do the outer MGF1
    memcpy( msg_hash,   r,       n );
    memcpy( msg_hash+n, pk_seed, n );
    mgf1<SHA512_CTX> stream( msg_hash, 2*n + sha512_output_size );
    stream.output( result, len_result );
}

} /* namespace sphincs_plus */
