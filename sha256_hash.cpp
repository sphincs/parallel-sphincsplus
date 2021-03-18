/*
 * This file has support for SHA-256-based parameter sets
 * This does those functions that are the same for both simple and
 * robust parameter sets
 */ 
#include <string.h>
#include "api.h"
#include "xn_internal.h"
#include "internal.h"
#include "sha256.h"
#include "sha256avx.h"

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
    unsigned char bufx8[8 * (max_len_hash + sha256_addr_bytes)];
    __m256i outbufx8[8][sha256_output_size / sizeof(__m256i)];
    unsigned int j;
    unsigned n = len_hash();
    const unsigned char* key = get_secret_seed();

    for (j = 0; j < 8; j++) {
        memcpy(bufx8 + j*(n + sha256_addr_bytes), key, n);
        memcpy(bufx8 + n + j*(n + sha256_addr_bytes),
                         addrx8 + j, sha256_addr_bytes);
    }

    sha256ctx8x ctx;
    sha256_init8x(&ctx);
    sha256_update8x(&ctx,
             bufx8 + 0*(n + sha256_addr_bytes),
             bufx8 + 1*(n + sha256_addr_bytes),
             bufx8 + 2*(n + sha256_addr_bytes),
             bufx8 + 3*(n + sha256_addr_bytes),
             bufx8 + 4*(n + sha256_addr_bytes),
             bufx8 + 5*(n + sha256_addr_bytes),
             bufx8 + 6*(n + sha256_addr_bytes),
             bufx8 + 7*(n + sha256_addr_bytes),
             n + sha256_addr_bytes);
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
    hash* h = get_message_hash();
    unsigned char block[max_message_block_size];
    unsigned char hash_output[max_message_hash_size];
    size_t n = len_hash();
    const unsigned char* prf = get_prf();

    // Do the inner hash
    h->init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x36 ^ prf[i];
    }
    memset( &block[n], 0x36, h->block_size()-n );
    h->update( block, h->block_size() );
    h->update( opt_rand, n );
    h->update( msg, len_msg );

    h->final(hash_output);

    // Do the outer hash
    h->init();
    for (size_t i=0; i<n; i++) {
	block[i] = 0x5c ^ prf[i];
    }
    memset( &block[n], 0x5c, h->block_size()-n );
    h->update( block, h->block_size() );
    h->update( hash_output, h->len_hash() );
    h->final( hash_output );

    memcpy( result, hash_output, n );

    zeroize( block, sizeof block );  // prf is supposed to be secret
    h->zeroize();
    delete h;
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void sha256_hash::h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) {
    unsigned char msg_hash[ 2*max_len_hash + max_message_hash_size + 4 ];
    size_t n = len_hash();

    const unsigned char *pk_seed = get_public_seed();
    const unsigned char *pk_root = get_root();

    hash* h = get_message_hash();

    memcpy( &msg_hash[ 0 * n ], r, n );
    memcpy( &msg_hash[ 1 * n ], pk_seed, n );
        // Not sure why Andreas didn't insert the root here...

    h->init();
    h->update(msg_hash, 2*n);  // r and the pk_seed
    h->update(pk_root, n);
    h->update(msg, len_msg);
    h->final(&msg_hash[ 2 * n]);
    size_t len_msg_hash = 2*n + h->len_hash();

    // Now do the outer MGF1
    for (unsigned index = 0; len_result > 0; index++) {
        unsigned size_batch = h->len_hash();
	if (size_batch > len_result) size_batch = len_result;

	ull_to_bytes( &msg_hash[ len_msg_hash ], 4, index );

	h->init();
	h->update( msg_hash, len_msg_hash+ 4 );
	unsigned char output_buffer[max_message_hash_size];
	h->final( output_buffer );
	memcpy( result, output_buffer, size_batch );

	result += size_batch;
	len_result -= size_batch;
    }

    delete h;
}

unsigned sha256_hash::num_track(void) {
    return 8;
}
unsigned sha256_hash::num_log_track(void) {
    return 3;
}

// The message hash for level 1 and 3; simple enough we just put it here
class sha256 : public hash {
    SHA256_CTX ctx;
public:
    virtual void init(void) { ctx.init(); }
    virtual void update(const void *m, size_t len) { ctx.update( m, len ); }
    virtual void final(void *m) { ctx.final((unsigned char*)m); }
    virtual size_t len_hash(void) { return sha256_output_size; }
    virtual size_t block_size(void) { return sha256_block_size; }
    virtual void zeroize(void) { sphincs_plus::zeroize( (void*)&ctx, sizeof ctx ); }
    virtual ~sha256(void) { ; }
};
hash* key_sha256_simple_13::get_message_hash(void) {
    return new sha256;
}
hash* key_sha256_robust_13::get_message_hash(void) {
    return new sha256;
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
