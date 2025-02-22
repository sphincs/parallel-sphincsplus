/*
 * This file has support for the low level SHA-256 routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha256avx.h"
#include "sha256.h"

namespace slh_dsa {

/**
 * The SHA-2 version of thash
 */
void key_sha2::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned char outbuf[sha256_output_size];

    // Retrieve precomputed state containing pub_seed
    SHA256_CTX ctx;
    ctx.init_from_intermediate(state_seeded, sha256_block_size);

    // Starting at state_seeded, hash the addr structure and the
    // input blocks
    ctx.update(addr, sha256_addr_bytes);
    ctx.update(in, inblocks * len_hash() );
    ctx.final(outbuf);

    memcpy(out, outbuf, len_hash());
}

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
void key_sha2::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx8)
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

    sha256_update8x(&ctx,
                    in[0],
                    in[1],
                    in[2],
                    in[3],
                    in[4],
                    in[5],
                    in[6],
                    in[7],
                    inblocks * n );

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

} /* slh_dsa */
