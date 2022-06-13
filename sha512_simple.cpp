/*
 * This file has support for the low level SHA-2-simple routines for L3, L5
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha512avx.h"
#include "sha512.h"

namespace sphincs_plus {

/**
 * The simple version of thash
 */
void key_sha256_L35_simple::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    // thash is never called with inblocks==1, hence we don't need to
    // special case that

    unsigned char outbuf[sha512_output_size];

    // Retrieve precomputed state containing pub_seed
    SHA512_CTX ctx;
    ctx.init_from_intermediate(state_seeded_512, sha512_block_size);

    // Starting at state_seeded, hash the addr structure and the
    // input blocks
    ctx.update(addr, sha256_addr_bytes);
    ctx.update(in, inblocks * len_hash() );
    ctx.final(outbuf);

    memcpy(out, outbuf, len_hash());
}

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 * Note that, for inblocks==1, the alternative f_xn function is used
 */
void key_sha256_L35_simple::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx8) {
    __m256i outbufx8[8][sha512_output_size / sizeof(__m256i)];
    sha512ctx4x ctx;

    int n = len_hash();
    for (int i=0; i<8; i+=4) {
        sha512_init_frombytes_x4(&ctx, state_seeded_512, 1024);

        sha512_update4x(&ctx,
                    &addrx8[i+0],
                    &addrx8[i+1],
                    &addrx8[i+2],
                    &addrx8[i+3],
                    sha256_addr_bytes );

        sha512_update4x(&ctx,
                    in[i+0],
                    in[i+1],
                    in[i+2],
                    in[i+3],
                    inblocks * n );

        sha512_final4x(&ctx,
                   outbufx8[i+0],
                   outbufx8[i+1],
                   outbufx8[i+2],
                   outbufx8[i+3]);
    }

    memcpy(out[0], outbufx8[0], n);
    memcpy(out[1], outbufx8[1], n);
    memcpy(out[2], outbufx8[2], n);
    memcpy(out[3], outbufx8[3], n);
    memcpy(out[4], outbufx8[4], n);
    memcpy(out[5], outbufx8[5], n);
    memcpy(out[6], outbufx8[6], n);
    memcpy(out[7], outbufx8[7], n);
}

//
// For the single input version of T, fall back to the base version, which
// uses SHA-256
void key_sha256_L35_simple::f_xn(unsigned char **out, unsigned char **in,
                                 addr_t* addrxn) {
    key_sha256_simple::thash_xn(out, in, 1, addrxn);
}

// This precomputes the SHA-512 hash state after processing the public seed
void key_sha256_L35_simple::initialize_public_seed(const unsigned char *pub_seed) {
    uint8_t block[sha512_block_size];
    size_t i;
    size_t n = len_hash();

    for (i = 0; i < n; ++i) {
        block[i] = pub_seed[i];
    }
    for (; i < sha512_block_size; ++i) {
        block[i] = 0;
    }

    SHA512_CTX ctx;
    ctx.init();
    ctx.update( block, sha512_block_size );
    ctx.export_intermediate( state_seeded_512 );

    // Also initialize the SHA-256 initial hash (which we also use)
    sha256_hash::initialize_public_seed(pub_seed);
}

} /* sphincs_plus */
