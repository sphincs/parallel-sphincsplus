/*
 * This file has support for SHA-256-based parameter sets
 * This does those functions that are the same for both simple and
 * robust parameter sets
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha256.h"
#include "sha256avx.h"
#include "mgf1.h"

namespace sphincs_plus {

// This precomputes the SHA-256 hash state after processing the public seed
void sha256_hash::initialize_public_seed(const unsigned char *pub_seed) {
    uint8_t block[sha256_block_size];
    size_t i;
    size_t n = len_hash();

    for (i = 0; i < n; ++i) {
        block[i] = pub_seed[i];
    }
    for (; i < sha256_block_size; ++i) {
        block[i] = 0;
    }

    SHA256_CTX ctx;
    ctx.init();
    ctx.update( block, sha256_block_size );
    ctx.export_intermediate( state_seeded );
}

void sha256_hash::set_public_key(const unsigned char *public_key) {
    key::set_public_key(public_key);
    initialize_public_seed( get_public_seed() );
}

void sha256_hash::set_private_key(const unsigned char *private_key) {
    key::set_private_key(private_key);
    initialize_public_seed( get_public_seed() );
}

/*
 * 8-way parallel version of prf_addr; takes 8x as much input and output
 * This is SHA-256 specific
 */
void sha256_hash::prf_addr_xn(unsigned char **out,
                const addr_t* addrx8)
{
    __m256i outbufx8[8][sha256_output_size / sizeof(__m256i)];
    sha256ctx8x ctx;

    sha256_init_frombytes_x8(&ctx, state_seeded, 512);

    int n = len_hash();
    sha256_update8x(&ctx,
                    &addrx8[0],
                    &addrx8[1],
                    &addrx8[2],
                    &addrx8[3],
                    &addrx8[4],
                    &addrx8[5],
                    &addrx8[6],
                    &addrx8[7],
                    sha256_addr_bytes );

    const unsigned char* key = get_secret_seed();
    sha256_update8x(&ctx,
		    key,
		    key,
		    key,
		    key,
		    key,
		    key,
		    key,
		    key,
                    n );

    sha256_final8x(&ctx,
                   outbufx8[0],
                   outbufx8[1],
                   outbufx8[2],
                   outbufx8[3],
                   outbufx8[4],
                   outbufx8[5],
                   outbufx8[6],
                   outbufx8[7]);

    memcpy(out[0], outbufx8[0], n);
    memcpy(out[1], outbufx8[1], n);
    memcpy(out[2], outbufx8[2], n);
    memcpy(out[3], outbufx8[3], n);
    memcpy(out[4], outbufx8[4], n);
    memcpy(out[5], outbufx8[5], n);
    memcpy(out[6], outbufx8[6], n);
    memcpy(out[7], outbufx8[7], n);
}

// prf_msg is defined as HMAC( prf, opt_rand || msg )
void sha256_hash::prf_msg( unsigned char *result,
              const unsigned char *opt_rand,
              const unsigned char *msg, size_t len_msg ) {
    SHA256_CTX ctx;
    unsigned char block[sha256_block_size];
    unsigned char hash_output[sha256_output_size];
    size_t n = len_hash();
    const unsigned char* prf = get_prf();

    // Do the inner hash
    ctx.init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x36 ^ prf[i];
    }
    memset( &block[n], 0x36, sha256_block_size-n );
    ctx.update( block, sha256_block_size );
    ctx.update( opt_rand, n );
    ctx.update( msg, len_msg );

    ctx.final(hash_output);

    // Do the outer hash
    ctx.init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x5c ^ prf[i];
    }
    memset( &block[n], 0x5c, sha256_block_size-n );
    ctx.update( block, sha256_block_size );
    ctx.update( hash_output, sha256_output_size );
    ctx.final( hash_output );

    memcpy( result, hash_output, n );

    zeroize( block, sizeof block );  // prf is supposed to be secret
    ctx.zeroize();
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void sha256_hash::h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) {
    unsigned char msg_hash[ sha256_output_size  + 2*max_len_hash ];
    size_t n = len_hash();

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    SHA256_CTX ctx;
    ctx.init();
    ctx.update(r, n);
    ctx.update(pk_seed, n);
    ctx.update(pk_root, n);
    ctx.update(msg, len_msg);
    ctx.final(msg_hash + 2*n);

    // Now do the outer MGF1
    memcpy( msg_hash,   r,       n );
    memcpy( msg_hash+n, pk_seed, n );
    mgf1<SHA256_CTX, sha256_output_size> stream( msg_hash,
                                                 2*n + sha256_output_size );
    stream.output( result, len_result );
}

unsigned sha256_hash::num_track(void) {
    return 8;
}
unsigned sha256_hash::num_log_track(void) {
    return 3;
}

sha256_hash::sha256_hash(void) {
    // We initialize the offset parameters to SHA-256 specific values
    offset_layer = 0; 
    offset_tree = 1;
    offset_type = 9;
    offset_kp_addr1 = 13;
    offset_kp_addr2 = 12;
    offset_chain_addr = 17;
    offset_hash_addr = 21;
    offset_tree_hgt = 17;
    offset_tree_index = 18;
}

} /* namespace sphincs_plus */
