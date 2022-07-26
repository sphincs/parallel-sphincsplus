/*
 * This file has support for the low level SHA-256-robust routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha256avx.h"
#include "sha256.h"
#include "mgf1.h"
#include "mgf1_8x.h"

namespace sphincs_plus {

/**
 * The robust version of thash
 */
void key_sha2_robust::thash( unsigned char* out,
             const unsigned char* in,
             unsigned int inblocks, addr_t addr) {
    unsigned char outbuf[sha256_output_size];
    unsigned n = len_hash();

    // Retrieve precomputed state containing pub_seed
    SHA256_CTX ctx;
    ctx.init_from_intermediate(state_seeded, sha256_block_size);

    // Initialize the seed for the MGF1 engine
    unsigned char mgf1_seed[ max_len_hash + sha2_addr_bytes ];
    memcpy( mgf1_seed, get_public_seed(), n );
    memcpy( &mgf1_seed[n], addr, sha2_addr_bytes );
    mgf1<SHA256_CTX> bitstream( mgf1_seed, n + sha2_addr_bytes );

    // Starting at state_seeded, hash the addr structure and the
    // input blocks xored with the mgf1 stream
    ctx.update(addr, sha2_addr_bytes);
    for (unsigned i = 0; i < inblocks; i++) {
        unsigned char buffer[max_len_hash];
        bitstream.output( buffer, n );
	for (unsigned j = 0; j < n; j++) {
	    buffer[j] ^= *in++;
	}
        ctx.update(buffer, n );
    }
    ctx.final(outbuf);

    memcpy(out, outbuf, len_hash());
}

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
void key_sha2_robust::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx8)
{
    sha256ctx8x ctx;
    int n = len_hash();

    sha256_init_frombytes_x8(&ctx, state_seeded, 512);

    sha256_update8x(&ctx,
                    &addrx8[0],
                    &addrx8[1],
                    &addrx8[2],
                    &addrx8[3],
                    &addrx8[4],
                    &addrx8[5],
                    &addrx8[6],
                    &addrx8[7],
                    sha2_addr_bytes );

    // Fire up the MGF1 engine
    unsigned char *ptr_seed[8];
    unsigned char seed[ 8*(max_len_hash + sha2_addr_bytes) ];
    for (int i=0; i<8; i++) {
	ptr_seed[i] = &seed[ i * (max_len_hash+sha2_addr_bytes) ];
	memcpy( ptr_seed[i], get_public_seed(), n );
	memcpy( ptr_seed[i]+n, &addrx8[i], sha2_addr_bytes );
    }
    mgf1_8x bit_stream( ptr_seed, n + sha2_addr_bytes );

    unsigned char buffer[8][max_len_hash];
    unsigned char *ptr_buffer[8];
    for (int i=0; i<8; i++) {
	ptr_buffer[i] = buffer[i];
    }
    for (unsigned k=0, block=0; k<inblocks; k++, block+=n) {
        bit_stream.output( ptr_buffer, n );
        for (int i=0; i<8; i++) {
	    for (int j=0; j<n; j++) {
		buffer[i][j] ^= in[i][j+block];
	    }
	}
        sha256_update8x(&ctx,
                    buffer[0],
                    buffer[1],
                    buffer[2],
                    buffer[3],
                    buffer[4],
                    buffer[5],
                    buffer[6],
                    buffer[7],
                    n );
    }
    __m256i outbufx8[8][sha256_output_size / sizeof(__m256i)];
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

} /* sphincs_plus */
