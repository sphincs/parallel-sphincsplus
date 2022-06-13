/*
 * This file has support for Haraka-based parameter sets
 * This does those functions that are the same for both simple and
 * robust parameter sets
 */ 
#include <string.h>
#include "api.h"
#include "internal.h"
#include "haraka.h"
#include "immintrin.h"

namespace sphincs_plus {

static void set_default_constants( u128* rc ) {
    rc[0] = _mm_set_epi32(0x0684704c,0xe620c00a,0xb2c5fef0,0x75817b9d);
    rc[1] = _mm_set_epi32(0x8b66b4e1,0x88f3a06b,0x640f6ba4,0x2f08f717);
    rc[2] = _mm_set_epi32(0x3402de2d,0x53f28498,0xcf029d60,0x9f029114);
    rc[3] = _mm_set_epi32(0x0ed6eae6,0x2e7b4f08,0xbbf3bcaf,0xfd5b4f79);
    rc[4] = _mm_set_epi32(0xcbcfb0cb,0x4872448b,0x79eecd1c,0xbe397044);
    rc[5] = _mm_set_epi32(0x7eeacdee,0x6e9032b7,0x8d5335ed,0x2b8a057b);
    rc[6] = _mm_set_epi32(0x67c28f43,0x5e2e7cd0,0xe2412761,0xda4fef1b);
    rc[7] = _mm_set_epi32(0x2924d9b0,0xafcacc07,0x675ffde2,0x1fc70b3b);
    rc[8] = _mm_set_epi32(0xab4d63f1,0xe6867fe9,0xecdb8fca,0xb9d465ee);
    rc[9] = _mm_set_epi32(0x1c30bf84,0xd4b7cd64,0x5b2a404f,0xad037e33);
    rc[10] = _mm_set_epi32(0xb2cc0bb9,0x941723bf,0x69028b2e,0x8df69800);
    rc[11] = _mm_set_epi32(0xfa0478a6,0xde6f5572,0x4aaa9ec8,0x5c9d2d8a);
    rc[12] = _mm_set_epi32(0xdfb49f2b,0x6b772a12,0x0efa4f2e,0x29129fd4);
    rc[13] = _mm_set_epi32(0x1ea10344,0xf449a236,0x32d611ae,0xbb6a12ee);
    rc[14] = _mm_set_epi32(0xaf044988,0x4b050084,0x5f9600c9,0x9ca8eca6);
    rc[15] = _mm_set_epi32(0x21025ed8,0x9d199c4f,0x78a2c7e3,0x27e593ec);
    rc[16] = _mm_set_epi32(0xbf3aaaf8,0xa759c9b7,0xb9282ecd,0x82d40173);
    rc[17] = _mm_set_epi32(0x6260700d,0x6186b017,0x37f2efd9,0x10307d6b);
    rc[18] = _mm_set_epi32(0x5aca45c2,0x21300443,0x81c29153,0xf6fc9ac6);
    rc[19] = _mm_set_epi32(0x9223973c,0x226b68bb,0x2caf92e8,0x36d1943a);
    rc[20] = _mm_set_epi32(0xd3bf9238,0x225886eb,0x6cbab958,0xe51071b4);
    rc[21] = _mm_set_epi32(0xdb863ce5,0xaef0c677,0x933dfddd,0x24e1128d);
    rc[22] = _mm_set_epi32(0xbb606268,0xffeba09c,0x83e48de3,0xcb2212b1);
    rc[23] = _mm_set_epi32(0x734bd3dc,0xe2e4d19c,0x2db91a4e,0xc72bf77d);
    rc[24] = _mm_set_epi32(0x43bb47c3,0x61301b43,0x4b1415c4,0x2cb3924e);
    rc[25] = _mm_set_epi32(0xdba775a8,0xe707eff6,0x03b231dd,0x16eb6899);
    rc[26] = _mm_set_epi32(0x6df3614b,0x3c755977,0x8e5e2302,0x7eca472c);
    rc[27] = _mm_set_epi32(0xcda75a17,0xd6de7d77,0x6d1be5b9,0xb88617f9);
    rc[28] = _mm_set_epi32(0xec6b43f0,0x6ba8e9aa,0x9d6c069d,0xa946ee5d);
    rc[29] = _mm_set_epi32(0xcb1e6950,0xf957332b,0xa2531159,0x3bf327c1);
    rc[30] = _mm_set_epi32(0x2cee0c75,0x00da619c,0xe4ed0353,0x600ed0d9);
    rc[31] = _mm_set_epi32(0xf0b1a5a1,0x96e90cab,0x80bbbabc,0x63a4a350);
    rc[32] = _mm_set_epi32(0xae3db102,0x5e962988,0xab0dde30,0x938dca39);
    rc[33] = _mm_set_epi32(0x17bb8f38,0xd554a40b,0x8814f3a8,0x2e75b442);
    rc[34] = _mm_set_epi32(0x34bb8a5b,0x5f427fd7,0xaeb6b779,0x360a16f6);
    rc[35] = _mm_set_epi32(0x26f65241,0xcbe55438,0x43ce5918,0xffbaafde);
    rc[36] = _mm_set_epi32(0x4ce99a54,0xb9f3026a,0xa2ca9cf7,0x839ec978);
    rc[37] = _mm_set_epi32(0xae51a51a,0x1bdff7be,0x40c06e28,0x22901235);
    rc[38] = _mm_set_epi32(0xa0c1613c,0xba7ed22b,0xc173bc0f,0x48a659cf);
    rc[39] = _mm_set_epi32(0x756acc03,0x02288288,0x4ad6bdfd,0xe9c59da1);
}

static void expand_seed( u128 *expanded, const unsigned char *pub_seed, size_t n ) {
    u128 default_rc[40]; 
    set_default_constants( default_rc );

    harakaS expander( default_rc );
    expander.absorb( pub_seed, n );
    expander.finalize();
    expander.squeeze( (unsigned char*)expanded, 40*16 );
}

void haraka_hash::set_public_key(const unsigned char *public_key) {
    key::set_public_key(public_key);
    expand_seed( pub_seed_expanded, get_public_seed(), len_hash() );
}

void haraka_hash::set_private_key(const unsigned char *private_key) {
    key::set_private_key(private_key);
    expand_seed( pub_seed_expanded, get_public_seed(), len_hash() );
}

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 * This is SHAKE-256 specific
 */
void haraka_hash::prf_addr_xn(unsigned char **out,
                const addr_t* addrx4)
{
    unsigned n = len_hash();
    union {
        unsigned char input_buffer[4][ addr_bytes + max_len_hash ];
	u128 input_u128[4][4];
    };
    const unsigned char* secret_seed = get_secret_seed();
    for (int i=0; i<4; i++) {
        memcpy( &input_buffer[i][0], addrx4+i, addr_bytes );
        memcpy( &input_buffer[i][32], secret_seed, n );
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

// prf_msg is defined as HarakaS_pk.seed( prf || optrand || msg )
void haraka_hash::prf_msg( unsigned char *result,
              const unsigned char *opt_rand,
              const unsigned char *msg, size_t len_msg ) {
    harakaS expander( pub_seed_expanded );
    unsigned n = len_hash();
    expander.absorb( get_prf(), n );
    expander.absorb( opt_rand, n );
    expander.absorb( msg, len_msg );
    expander.finalize();
    expander.squeeze( result, n );
}

// Here, len_result is not the size of the buffer (which it is in most
// similar contexts); instead, it is the number of output bytes desired
void haraka_hash::h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) {
    harakaS expander( pub_seed_expanded );
    unsigned n = len_hash();
    expander.absorb( r, n );
    expander.absorb( get_root(), n );
    expander.absorb( msg, len_msg );
    expander.finalize();
    expander.squeeze( result, len_result );
}

unsigned haraka_hash::num_track(void) {
    return 4;
}
unsigned haraka_hash::num_log_track(void) {
    return 2;
}

} /* namespace sphincs_plus */
