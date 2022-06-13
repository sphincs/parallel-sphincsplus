/*
 * The 4 track version of MGF1 based on SHA-512; it generates 4 outputs in
 * parallel, using the AVX2 4-way parallel hash implementation
 *
 * This is in its own file because it is used only by the L3/L5 SHA2 robust
 * parameter sets
 */

#include <string.h>
#include "mgf1_512_4x.h"
#include "sha512avx.h"

namespace sphincs_plus {

mgf1_sha512_4x::mgf1_sha512_4x( unsigned char **seed_vector, unsigned seed_len ) {
    for (int i=0; i<4; i++) {
        memcpy( state[i], seed_vector[i], seed_len );
    }
    state_len = seed_len;
    next_index = 0;
    output_index = sha512_output_size;
}

void mgf1_sha512_4x::output( unsigned char **buffer, unsigned len_output ) {
    unsigned inserted = 0;  // Number of bytes we have already generated
    for (;;) {
        unsigned left_in_buffer = sha512_output_size - output_index;
	if (left_in_buffer > len_output) {
	    left_in_buffer = len_output;
	}
	if (left_in_buffer > 0) {
	    for (int i=0; i<4; i++) {
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
	for (int i=0; i<4; i++) {
            memcpy( &state[i][ state_len ], index, 4 );
	}
	next_index += 1;
        sha512ctx4x ctx;
        sha512_init4x(&ctx);
        sha512_update4x(&ctx,
                 state[0],
                 state[1],
                 state[2],
                 state[3],
		 state_len+4);
        sha512_final4x(&ctx,
	         output_buffer[0],
	         output_buffer[1],
	         output_buffer[2],
	         output_buffer[3]);
	output_index = 0;
    }
}

}  /* namespace sphincs_plus */

