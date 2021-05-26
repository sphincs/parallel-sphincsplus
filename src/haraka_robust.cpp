/*
 * This file has support for the low level Harak-robust routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "haraka.h"

namespace sphincs_plus {

static void memxor( unsigned char *dest, const unsigned char *src, unsigned count ) {
    while (count--) {
        *dest++ ^= *src++;
    }
}

/**
 * The robust version of thash
 */
void key_haraka_robust::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned n = len_hash();

    harakaS mask( pub_seed_expanded );
    mask.absorb( addr, addr_bytes  );
    mask.finalize();

    harakaS expander( pub_seed_expanded );
    expander.absorb( addr, addr_bytes  );
    for (unsigned i=0; i<inblocks; i++, in += n) {
        unsigned char buffer[ max_len_hash ];
        mask.squeeze( buffer, n );
	memxor( buffer, in, n );
        expander.absorb( buffer, n );
    }
    expander.finalize();
    expander.squeeze( out, n );
}

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void key_haraka_robust::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx4) {
    unsigned n = len_hash();
    unsigned char *addr_vector[4];
    addr_vector[0] = addrx4[0];
    addr_vector[1] = addrx4[1];
    addr_vector[2] = addrx4[2];
    addr_vector[3] = addrx4[3];

    harakaS_4x mask( pub_seed_expanded );
    mask.absorb( addr_vector, addr_bytes  );
    mask.finalize();

    harakaS_4x expander( pub_seed_expanded );
    expander.absorb( addr_vector, addr_bytes );

    unsigned char buffer[4][ max_len_hash ];
    unsigned char *vector[4];
    for (int i=0; i<4; i++) vector[i] = buffer[i];

    unsigned input_offset = 0;
    for (unsigned i=0; i<inblocks; i++, input_offset += n) {
        mask.squeeze( vector, n );

	for (int m=0; m<4; m++) {
            memxor( buffer[m], &in[m][input_offset], n );
	}
        expander.absorb( vector, n );
    }
    expander.finalize();
    expander.squeeze( out, n );
}

void key_haraka_robust::f_xn(unsigned char **out, unsigned char **in,
                             addr_t* addrxn) {
    unsigned n = len_hash();
    union {
        u128 input_buffer[4][4];
        unsigned char char_buffer[4][64];
    };

    for (int i=0; i<4; i++) {
        memcpy( &input_buffer[i][0], addrxn+i, addr_bytes );
    }
    haraka256_4x mask( pub_seed_expanded );
    mask.transform( &input_buffer[0][2], &input_buffer[1][2],
                    &input_buffer[2][2], &input_buffer[3][2],
                    &input_buffer[0][0], &input_buffer[1][0],
                    &input_buffer[2][0], &input_buffer[3][0] );

    for (int i=0; i<4; i++) {
        memxor( &char_buffer[i][32], in[i], n );
	memset( &char_buffer[i][32+n], 0, 32-n );
    }

    u128 output_buffer[4][2];

    haraka512_4x prf( pub_seed_expanded );
    prf.transform( output_buffer[0], output_buffer[1],
	           output_buffer[2], output_buffer[3],
	           input_buffer[0], input_buffer[1],
	           input_buffer[2], input_buffer[3] );
   
    for (int i=0; i<4; i++) {
        memcpy(out[i], output_buffer[i], n);
    }
}

} /* sphincs_plus */
