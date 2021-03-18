/*
Plain C++ implementation of the Haraka256 and Haraka512 permutations.
*
* Random thought: is just dumping everything into the haraka_hash class the
* right approach???
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "api.h"
#include "immintrin.h"
#include "haraka.h"

namespace sphincs_plus {

const size_t HARAKAS_RATE = 32;

#define LOAD(src) _mm_load_si128((u128 *)(src))
#define STORE(dest,src) _mm_storeu_si128((u128 *)(dest),src)

#define XOR128(a, b) _mm_xor_si128(a, b)

#define AES2(s0, s1, rci) \
  s0 = _mm_aesenc_si128(s0, *(rci)); \
  s1 = _mm_aesenc_si128(s1, *(rci + 1)); \
  s0 = _mm_aesenc_si128(s0, *(rci + 2)); \
  s1 = _mm_aesenc_si128(s1, *(rci + 3));

#define AES2_4x(s0, s1, s2, s3, rci) \
  AES2(s0[0], s0[1], rci); \
  AES2(s1[0], s1[1], rci); \
  AES2(s2[0], s2[1], rci); \
  AES2(s3[0], s3[1], rci);

#define AES4(s0, s1, s2, s3, rci) \
  s0 = _mm_aesenc_si128(s0, *(rci)); \
  s1 = _mm_aesenc_si128(s1, *(rci + 1)); \
  s2 = _mm_aesenc_si128(s2, *(rci + 2)); \
  s3 = _mm_aesenc_si128(s3, *(rci + 3)); \
  s0 = _mm_aesenc_si128(s0, *(rci + 4)); \
  s1 = _mm_aesenc_si128(s1, *(rci + 5)); \
  s2 = _mm_aesenc_si128(s2, *(rci + 6)); \
  s3 = _mm_aesenc_si128(s3, *(rci + 7));

#define AES4_4x(s0, s1, s2, s3, rci) \
  AES4(s0[0], s0[1], s0[2], s0[3], rci); \
  AES4(s1[0], s1[1], s1[2], s1[3], rci); \
  AES4(s2[0], s2[1], s2[2], s2[3], rci); \
  AES4(s3[0], s3[1], s3[2], s3[3], rci);

#define MIX2(s0, s1) \
  tmp = _mm_unpacklo_epi32(s0, s1); \
  s1 = _mm_unpackhi_epi32(s0, s1); \
  s0 = tmp;

#define MIX4(s0, s1, s2, s3) \
  tmp  = _mm_unpacklo_epi32(s0, s1); \
  s0 = _mm_unpackhi_epi32(s0, s1); \
  s1 = _mm_unpacklo_epi32(s2, s3); \
  s2 = _mm_unpackhi_epi32(s2, s3); \
  s3 = _mm_unpacklo_epi32(s0, s2); \
  s0 = _mm_unpackhi_epi32(s0, s2); \
  s2 = _mm_unpackhi_epi32(s1, tmp); \
  s1 = _mm_unpacklo_epi32(s1, tmp);

#define TRUNCSTORE(out, s0, s1, s2, s3) \
  _mm_storeu_si128(out, \
                   (__m128i)_mm_shuffle_pd((__m128d)(s0), (__m128d)(s1), 3)); \
  _mm_storeu_si128((out + 1), \
                   (__m128i)_mm_shuffle_pd((__m128d)(s2), (__m128d)(s3), 0));

// This transforms the data in place
void haraka512::permute( u128* s ) {
    u128 tmp;
  
    AES4(s[0], s[1], s[2], s[3], rc);
    MIX4(s[0], s[1], s[2], s[3]);
  
    AES4(s[0], s[1], s[2], s[3], rc + 8);
    MIX4(s[0], s[1], s[2], s[3]);
  
    AES4(s[0], s[1], s[2], s[3], rc + 16);
    MIX4(s[0], s[1], s[2], s[3]);
  
    AES4(s[0], s[1], s[2], s[3], rc + 24);
    MIX4(s[0], s[1], s[2], s[3]);
  
    AES4(s[0], s[1], s[2], s[3], rc + 32);
    MIX4(s[0], s[1], s[2], s[3]);
}

void harakaS::absorb( const unsigned char* msg, unsigned len_msg ) {
    while (len_msg > 0) {
        unsigned bytes = len_msg;
	if (bytes + index > HARAKAS_RATE) {
	    bytes = HARAKAS_RATE - index;
	}
	for (unsigned i = 0; i<bytes; i++) {
	    buffer[i + index] ^= msg[i];
	}
        len_msg -= bytes;
	msg += bytes;
	index += bytes;
	if (index == HARAKAS_RATE) {
            perm.permute( long_buffer );
	    index = 0;
	}
    }
}

void harakaS::finalize(void) {
    unsigned char marker[1];
    if (index == HARAKAS_RATE-1) {
        marker[0] = 0x1f ^ 0x80;  // The trailing marker and last-bit are in
                                  // the same byte
    } else {
        marker[0] = 0x1f;
        absorb( marker, 1 );
        index = HARAKAS_RATE-1;
        marker[0] = 0x80;
    }
    absorb( marker, 1 );   /* This will cause a permutation */
}

void harakaS::squeeze( unsigned char* output, unsigned len_output ) {
    while (len_output > 0) {
	if (index == HARAKAS_RATE) {
            perm.permute( long_buffer );
	    index = 0;
	}

        unsigned bytes = len_output;
	if (bytes + index > HARAKAS_RATE) {
	    bytes = HARAKAS_RATE - index;
	}
	memcpy( output, buffer+index, bytes);
        len_output -= bytes;
	output += bytes;
	index += bytes;
    }
}

void haraka512_4x::permute( u128 *s0, u128 *s1, u128 *s2, u128 *s3,
                            const u128 *in_0, const u128 *in_1,
                            const u128 *in_2, const u128 *in_3) {
    u128 tmp;
   
    memcpy( s0, in_0, 4 * sizeof(u128) ); 
    memcpy( s1, in_1, 4 * sizeof(u128) ); 
    memcpy( s2, in_2, 4 * sizeof(u128) ); 
    memcpy( s3, in_3, 4 * sizeof(u128) ); 
    
    AES4_4x(s0, s1, s2, s3, rc);
    MIX4(s0[0], s0[1], s0[2], s0[3]);
    MIX4(s1[0], s1[1], s1[2], s1[3]);
    MIX4(s2[0], s2[1], s2[2], s2[3]);
    MIX4(s3[0], s3[1], s3[2], s3[3]);
    
    AES4_4x(s0, s1, s2, s3, rc + 8);
    MIX4(s0[0], s0[1], s0[2], s0[3]);
    MIX4(s1[0], s1[1], s1[2], s1[3]);
    MIX4(s2[0], s2[1], s2[2], s2[3]);
    MIX4(s3[0], s3[1], s3[2], s3[3]);
    
    AES4_4x(s0, s1, s2, s3, rc + 16);
    MIX4(s0[0], s0[1], s0[2], s0[3]);
    MIX4(s1[0], s1[1], s1[2], s1[3]);
    MIX4(s2[0], s2[1], s2[2], s2[3]);
    MIX4(s3[0], s3[1], s3[2], s3[3]);
    
    AES4_4x(s0, s1, s2, s3, rc + 24);
    MIX4(s0[0], s0[1], s0[2], s0[3]);
    MIX4(s1[0], s1[1], s1[2], s1[3]);
    MIX4(s2[0], s2[1], s2[2], s2[3]);
    MIX4(s3[0], s3[1], s3[2], s3[3]);
    
    AES4_4x(s0, s1, s2, s3, rc + 32);
    MIX4(s0[0], s0[1], s0[2], s0[3]);
    MIX4(s1[0], s1[1], s1[2], s1[3]);
    MIX4(s2[0], s2[1], s2[2], s2[3]);
    MIX4(s3[0], s3[1], s3[2], s3[3]);
}

void haraka512_4x::transform( u128 *out0, u128 *out1, u128 *out2, u128 *out3,
                            const u128 *in_0, const u128 *in_1,
                            const u128 *in_2, const u128 *in_3) {
    u128 s[4][4];
   
    permute( s[0], s[1], s[2], s[3],
             in_0, in_1, in_2, in_3 );

    TRUNCSTORE(out0, s[0][0]^in_0[0],
                     s[0][1]^in_0[1],
                     s[0][2]^in_0[2],
                     s[0][3]^in_0[3]);
    TRUNCSTORE(out1, s[1][0]^in_1[0],
                     s[1][1]^in_1[1],
                     s[1][2]^in_1[2],
                     s[1][3]^in_1[3]);
    TRUNCSTORE(out2, s[2][0]^in_2[0],
                     s[2][1]^in_2[1],
                     s[2][2]^in_2[2],
                     s[2][3]^in_2[3]);
    TRUNCSTORE(out3, s[3][0]^in_3[0],
                     s[3][1]^in_3[1],
                     s[3][2]^in_3[2],
                     s[3][3]^in_3[3]);
}

void harakaS_4x::absorb( unsigned char** msg, unsigned len_msg ) {
    unsigned msg_processed = 0;
    while (len_msg > 0) {
        unsigned bytes = len_msg;
	if (bytes + index > HARAKAS_RATE) {
	    bytes = HARAKAS_RATE - index;
	}
	for (int j=0; j<4; j++) {
            unsigned char* m = msg[j] + msg_processed;
            for (unsigned i = 0; i<bytes; i++) {
	        buffer[j][i + index] ^= m[i];
	    }
	}
        len_msg -= bytes;
	msg_processed += bytes;
	index += bytes;
	if (index == HARAKAS_RATE) {
            perm.permute( u128_buffer[0], u128_buffer[1],
                          u128_buffer[2], u128_buffer[3],
                          u128_buffer[0], u128_buffer[1],
                          u128_buffer[2], u128_buffer[3] );
	    index = 0;
	}
    }
}

void harakaS_4x::finalize(void) {
    unsigned char marker[1];
    unsigned char* vector[4];
    vector[0] = vector[1] = vector[2] = vector[3] = marker;
    marker[0] = 0x1f;
    absorb( vector, 1 );
    index = HARAKAS_RATE-1;
    marker[0] = 0x80;
    absorb( vector, 1 );   /* This will cause a permutation */
}

void harakaS_4x::squeeze( unsigned char** output, unsigned len_output ) {
    unsigned output_so_far = 0;
    while (len_output > 0) {
	if (index == HARAKAS_RATE) {
            perm.permute( u128_buffer[0], u128_buffer[1],
                          u128_buffer[2], u128_buffer[3],
                          u128_buffer[0], u128_buffer[1],
                          u128_buffer[2], u128_buffer[3] );
	    index = 0;
	}

        unsigned bytes = len_output;
	if (bytes + index > HARAKAS_RATE) {
	    bytes = HARAKAS_RATE - index;
	}
	for (int j=0; j<4; j++) {
	    memcpy( output[j] + output_so_far, &buffer[j][index], bytes);
	}
        len_output -= bytes;
	output_so_far += bytes;
	index += bytes;
    }
}

void haraka256_4x::transform( u128* s0, u128* s1, u128* s2, u128* s3,
                              const u128 *in0, const u128 *in1,
                              const u128 *in2, const u128 *in3 ) {
    u128 tmp;

    memcpy( s0, in0, 2*sizeof(u128) );
    memcpy( s1, in1, 2*sizeof(u128) );
    memcpy( s2, in2, 2*sizeof(u128) );
    memcpy( s3, in3, 2*sizeof(u128) );

    // Round 1
    AES2_4x(s0, s1, s2, s3, rc);

    MIX2(s0[0], s0[1]);
    MIX2(s1[0], s1[1]);
    MIX2(s2[0], s2[1]);
    MIX2(s3[0], s3[1]);

    // Round 2
    AES2_4x(s0, s1, s2, s3, rc + 4);

    MIX2(s0[0], s0[1]);
    MIX2(s1[0], s1[1]);
    MIX2(s2[0], s2[1]);
    MIX2(s3[0], s3[1]);

    // Round 3
    AES2_4x(s0, s1, s2, s3, rc + 8);

    MIX2(s0[0], s0[1]);
    MIX2(s1[0], s1[1]);
    MIX2(s2[0], s2[1]);
    MIX2(s3[0], s3[1]);

    // Round 4
    AES2_4x(s0, s1, s2, s3, rc + 12);

    MIX2(s0[0], s0[1]);
    MIX2(s1[0], s1[1]);
    MIX2(s2[0], s2[1]);
    MIX2(s3[0], s3[1]);

    // Round 5
    AES2_4x(s0, s1, s2, s3, rc + 16);

    MIX2(s0[0], s0[1]);
    MIX2(s1[0], s1[1]);
    MIX2(s2[0], s2[1]);
    MIX2(s3[0], s3[1]);

    // Feed Forward
    s0[0] ^= in0[0];
    s0[1] ^= in0[1];
    s1[0] ^= in1[0];
    s1[1] ^= in1[1];
    s2[0] ^= in2[0];
    s2[1] ^= in2[1];
    s3[0] ^= in3[0];
    s3[1] ^= in3[1];
}

} /* namespace sphincs_plus */
