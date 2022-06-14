/*
 * This file has support for the low level SHA-2-robust routines for L3, L5
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "sha512avx.h"
#include "sha512.h"
#include "mgf1.h"
#include "mgf1_512_4x.h"

namespace sphincs_plus {

static void xor_mem(unsigned char* dest, const unsigned char* src, unsigned n) {
    while (n--)
	*dest++ ^= *src++;
}

/**
 * The robust version of thash
 */
void key_sha2_L35_robust::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    // thash is never called with inblocks==1, hence we don't need to
    // special case that
 
    unsigned char outbuf[sha512_output_size];
    unsigned n = len_hash();

    // Retrieve precomputed state containing pub_seed
    SHA512_CTX ctx;
    ctx.init_from_intermediate(state_seeded_512, sha512_block_size);

    // Initialize the seed for the MGF1 engine
    unsigned char mgf1_seed[ max_len_hash + sha2_addr_bytes ];
    memcpy( mgf1_seed, get_public_seed(), n );
    memcpy( &mgf1_seed[n], addr, sha2_addr_bytes );
    mgf1<SHA512_CTX> bitstream( mgf1_seed, n + sha2_addr_bytes );

    // Starting at state_seeded, hash the addr structure and the
    // input blocks xored with the mgf1 stream
    ctx.update(addr, sha2_addr_bytes);
    for (unsigned i = 0; i < inblocks; i++) {
        unsigned char buffer[max_len_hash];
        bitstream.output( buffer, n );
	xor_mem(buffer, in, n);
	in += n;
        ctx.update( buffer, n );
    }
    ctx.final(outbuf);

    memcpy(out, outbuf, len_hash());
}

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 * Note that, for inblocks==1, the alternative f_xn function is used
 */
void key_sha2_L35_robust::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx8)
{
    sha512ctx4x ctx;
    int n = len_hash();
    unsigned char *mask_seed[4];
    unsigned char seed[ 4*(max_len_hash + sha2_addr_bytes) ];
    for (int j=0; j<4; j++) {
	mask_seed[j] = &seed[ j * (max_len_hash+sha2_addr_bytes) ];
    }
    unsigned char buffer[4][max_len_hash];
    unsigned char *ptr_buffer[4];
    for (int j=0; j<4; j++) {
	ptr_buffer[j] = buffer[j];
    }
    __m256i outbufx8[8][sha512_output_size / sizeof(__m256i)];

    // Note: the API says '8-way', however the SHA512-AVX2 code we have
    // does '4-way'.  Account for this by iterating through the AVX2 code
    // twice
    for (int i=0; i<8; i+=4) {

        sha512_init_frombytes_x4(&ctx, state_seeded_512, 1024);

        sha512_update4x(&ctx,
                    &addrx8[i+0],
                    &addrx8[i+1],
                    &addrx8[i+2],
                    &addrx8[i+3],
                    sha2_addr_bytes );

        // Fire up the MGF1 engine that'll generate the masks
        for (int j=0; j<4; j++) {
	    memcpy( mask_seed[j], get_public_seed(), n );
            memcpy( mask_seed[j]+n, &addrx8[i+j], sha2_addr_bytes );
	}
        mgf1_sha512_4x bit_stream( mask_seed, n + sha2_addr_bytes );

	// Stir in the input blocks (including the mask)
        for (unsigned k=0, block=0; k<inblocks; k++, block+=n) {
	    // Generate the mask
            bit_stream.output( ptr_buffer, n );
	    // Xor the mask and the input blocks
            for (int j=0; j<4; j++) {
		xor_mem( ptr_buffer[j], &in[i+j][block], n );
	    }
	    // Include that xor in with the hash
            sha512_update4x(&ctx,
                    ptr_buffer[0],
                    ptr_buffer[1],
                    ptr_buffer[2],
                    ptr_buffer[3],
                    n );
	}
 
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
void key_sha2_L35_robust::f_xn(unsigned char **out, unsigned char **in,
                                 addr_t* addrxn) {
    key_sha2_robust::thash_xn(out, in, 1, addrxn);
}

// This precomputes the SHA-512 hash state after processing the public seed
void key_sha2_L35_robust::initialize_public_seed(const unsigned char *pub_seed) {
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

    // Also initialize the SHA-2 initial hash (which we also use)
    sha2_hash::initialize_public_seed(pub_seed);
}

} /* sphincs_plus */
