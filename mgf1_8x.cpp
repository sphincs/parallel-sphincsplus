/*
 * The 8 track version of MGF1; it generates 8 outputs in parallel, using the
 * AVX2 8-way parallel hash implementation
 *
 * This is in its own file because it is used only by the SHA-256 robust
 * parameter sets
 */

#include <string.h>
#include "mgf1_8x.h"
#include "sha256avx.h"

namespace sphincs_plus {

mgf1_8x::mgf1_8x( unsigned char **seed_vector, unsigned seed_len ) {
    for (int i=0; i<8; i++) {
        memcpy( state[i], seed_vector[i], seed_len );
    }
    state_len = seed_len;
    next_index = 0;
    output_index = sha256_output_size;
}

void mgf1_8x::output( unsigned char **buffer, unsigned len_output ) {
    unsigned inserted = 0;  // Number of bytes we have already generated
    for (;;) {
        unsigned left_in_buffer = sha256_output_size - output_index;
	if (left_in_buffer > len_output) {
	    left_in_buffer = len_output;
	}
	if (left_in_buffer > 0) {
	    for (int i=0; i<8; i++) {
	        memcpy( buffer[i] + inserted,
                        &char_output_buffer[i][output_index],
                        left_in_buffer );
	    }
	    output_index += left_in_buffer;
	    inserted += left_in_buffer;
	    len_output -= left_in_buffer;
	}
	if (len_output == 0) break;

	// We need to generate some fresh output
	unsigned char index[4];
	ull_to_bytes( index, 4, next_index );
	for (int i=0; i<8; i++) {
            memcpy( &state[i][ state_len ], index, 4 );
	}
	next_index += 1;
        sha256ctx8x ctx;
        sha256_init8x(&ctx);
        sha256_update8x(&ctx,
                 state[0],
                 state[1],
                 state[2],
                 state[3],
                 state[4],
                 state[5],
                 state[6],
                 state[7],
		 state_len+4);
        sha256_final8x(&ctx,
	         output_buffer[0],
	         output_buffer[1],
	         output_buffer[2],
	         output_buffer[3],
	         output_buffer[4],
	         output_buffer[5],
	         output_buffer[6],
	         output_buffer[7]);
	output_index = 0;
    }
}

}  /* namespace sphincs_plus */

