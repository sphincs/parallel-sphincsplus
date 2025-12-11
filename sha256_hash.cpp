/*
 * This file has support for SHA-256-based parameter sets
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha256.h"
#include "sha256avx.h"
#include "sha256avx512.h"
#include "mgf1.h"

namespace slh_dsa {

// This precomputes the SHA-256 hash state after processing the public seed
void key_sha2::initialize_public_seed(const unsigned char *pub_seed) {
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

void key_sha2::set_public_key(const unsigned char *public_key) {
    key::set_public_key(public_key);
    initialize_public_seed( get_public_seed() );
}

void key_sha2::set_private_key(const unsigned char *private_key) {
    key::set_private_key(private_key);
    initialize_public_seed( get_public_seed() );
}

/*
 * 8 or 16-way parallel version of prf_addr; takes 8x or 16x as much input and output
 * This is SHA-256 specific
 */
void key_sha2::prf_addr_xn(unsigned char **out,
                const addr_t* addrx)
{
    int n = len_hash();
    const unsigned char* key = get_secret_seed();

    if (do_avx512) {
        SHA256_16x_CTX ctx( state_seeded, 1 );

        unsigned char *pointer[16];
        for (int i=0; i<16; i++) {
            pointer[i] = const_cast<unsigned char*>(addrx[i]);
        }
        ctx.update(pointer, sha256_addr_bytes );
        for (int i=0; i<16; i++) {
            pointer[i] = const_cast<unsigned char *>(key);
        }
        ctx.update(pointer, n);
        if (n == 32) {
            ctx.final(out);   // No truncation needed
        } else {
            unsigned char outbuff[16][32];
            for (int i=0; i<16; i++) {
                pointer[i] = outbuff[i];
            }
            ctx.final(pointer);
            for (int i=0; i<16; i++) {
                memcpy(out[i], outbuff[i], n);
            }
        }
    } else {
        __m256i outbufx8[8][sha256_output_size / sizeof(__m256i)];
        sha256ctx8x ctx;
    
        sha256_init_frombytes_x8(&ctx, state_seeded, 512);
    
        sha256_update8x(&ctx,
                        &addrx[0],
                        &addrx[1],
                        &addrx[2],
                        &addrx[3],
                        &addrx[4],
                        &addrx[5],
                        &addrx[6],
                        &addrx[7],
                        sha256_addr_bytes );
    
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
}

// prf_msg is defined as HMAC( prf, opt_rand || msg )
void key_sha2::prf_msg( unsigned char *result,
              const unsigned char *opt_rand,
              unsigned char domain_separator_byte,
              const void *context, size_t len_context,
              const void *oid, size_t len_oid,
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
    ctx.update( &domain_separator_byte, 1 );
    unsigned char c = len_context;
    ctx.update( &c, 1 );
    if (len_context > 0) {
        ctx.update( context, len_context );
    }
    if (len_oid > 0) {
        ctx.update( oid, len_oid );
    }
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
void key_sha2::h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              unsigned char domain_separator_byte,
              const void *context, size_t len_context,
              const void *oid, size_t len_oid,
              const void *msg, size_t len_msg ) {
    unsigned char msg_hash[ sha256_output_size  + 2*max_len_hash ];
    size_t n = len_hash();

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    SHA256_CTX ctx;
    ctx.init();
    ctx.update(r, n);
    ctx.update(pk_seed, n);
    ctx.update(pk_root, n);
    ctx.update(&domain_separator_byte, 1);
    unsigned char c = len_context;
    ctx.update( &c, 1 );
    if (len_context > 0) {
        ctx.update(context, len_context);
    }
    if (len_oid > 0) {
        ctx.update(oid, len_oid);
    }
    ctx.update(msg, len_msg);
    ctx.final(msg_hash + 2*n);

    // Now do the outer MGF1
    memcpy( msg_hash,   r,       n );
    memcpy( msg_hash+n, pk_seed, n );
    mgf1<SHA256_CTX> stream( msg_hash, 2*n + sha256_output_size );
    stream.output( result, len_result );
}

key_sha2::key_sha2(void) {
    // We initialize the offset parameters to SHA-2 specific values
    offset_layer = 0; 
    offset_tree = 1;
    offset_type = 9;
    offset_kp_addr1 = 13;
    offset_kp_addr2 = 12;
    offset_chain_addr = 17;
    offset_hash_addr = 21;
    offset_tree_hgt = 17;
    offset_tree_index = 18;

    // and reset the default number of tracks to assume no AVX-512
    // We may update it later when we learn the parameter set
    do_avx512 = do_avx512_verify = false;
    num_track_ = num_track_verify_ = 8;
    num_log_track_ = num_log_track_verify_ = 3;
}

//
// This is here because whether we can do AVX-512 depends on the SLH-DSA
// parameter sets - we can't sign or key gen if the Merkle trees are of
// height 3
void key_sha2::set_geometry( size_t len_hash, size_t k, size_t t, size_t h,
                       size_t d, size_t wots_digits ) {
    key::set_geometry( len_hash, k, t, h, d, wots_digits );

    // Check for AVX-512 support
    if (check_avx512()) {
        do_avx512_verify = true;   // AVX-512 supported; we can verify with
        num_track_verify_ = 16;    // it, for all parameter sets
        num_log_track_verify_ = 4;
        if (h > 3*d) {
            do_avx512 = true;      // The Merkle trees are bigger than 3
            num_track_= 16;        // We can use AVX-512 for all operations
            num_log_track_ = 4;
        }
    }
}

} /* namespace slh_dsa */
