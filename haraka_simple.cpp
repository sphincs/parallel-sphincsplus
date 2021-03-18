/*
 * This file has support for the low level Harak-simple routines
 */
#include <string.h>
#include "api.h"
#include "internal.h"
#include "haraka.h"

namespace sphincs_plus {

/**
 * The simple version of thash
 */
void key_haraka_simple::thash( unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) {
    unsigned n = len_hash();

    harakaS expander( pub_seed_expanded );
    expander.absorb( addr, addr_bytes  );
    expander.absorb( in, inblocks * n );
    expander.finalize();
    expander.squeeze( out, n );
}

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void key_haraka_simple::thash_xn(unsigned char **out,
             unsigned char **in,
             unsigned int inblocks,
             addr_t* addrx4) {
    unsigned n = len_hash();
    unsigned char *addr_vector[4];
    addr_vector[0] = addrx4[0];
    addr_vector[1] = addrx4[1];
    addr_vector[2] = addrx4[2];
    addr_vector[3] = addrx4[3];

    harakaS_4x expander( pub_seed_expanded );
    expander.absorb( addr_vector, addr_bytes );
    expander.absorb( in, n * inblocks );
    expander.finalize();
    expander.squeeze( out, n );
}

void key_haraka_simple::f_xn(unsigned char **out, unsigned char **in,
                             addr_t* addrx4) {
    unsigned n = len_hash();
    union {
        unsigned char input_buffer[4][ addr_bytes + max_len_hash ];
	u128 input_u128[4][4];
    };
    for (int i=0; i<4; i++) {
        memcpy( &input_buffer[i][0], addrx4+i, addr_bytes );
        memcpy( &input_buffer[i][32], in[i], n );
        memset( &input_buffer[i][32+n], 0, 32-n );
    }

    u128 output_buffer[4][2];

    haraka512_4x prf( pub_seed_expanded );
    prf.transform( output_buffer[0], output_buffer[1],
	           output_buffer[2], output_buffer[3],
	           input_u128[0], input_u128[1],
	           input_u128[2], input_u128[3] );
   
    for (int i=0; i<4; i++) {
        memcpy(out[i], output_buffer[i], n);
    }
}

} /* sphincs_plus */
