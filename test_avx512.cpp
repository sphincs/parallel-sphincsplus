#include <cstdio>
#include <stdbool.h>
#include <cstring>
#include <memory>
#include "api.h"
#include "test_sphincs.h"
#include "sha256avx512.h"
#include "sha512avx512.h"
#include "shake256avx512.h"
#include "sha256.h"
#include "sha512.h"

//
// This tests out the AVX-512 implementations of the hash functions

//
// Check if we can do AVX-512 instructions
bool enable_avx512(bool) {
    if (!slh_dsa::check_avx512()) {
        printf( "  Test skipped - AVX-512 instructions not available\n" );
        return false;
    }
    return true;
}

static unsigned char garbage(void) {
    static uint64_t seed = 1;
    seed += (seed * seed) | 5;
    return seed >> 48;
}

//
// Our SHA-256 implementation does 16 SHA-256 hashes at once.  What we do is
// for each one of the 16 lanes, we insert the message, and for the other 15
// lanes, we insert random data.  Then, after the hash, we check if the output
// lane has the expected value (and we ignore the others because, well, random
// data)
static bool test_sha256( const unsigned char *message, size_t message_len, const unsigned char *expected_hash, bool fast_flag ) {
    auto mem = std::make_unique<unsigned char[]>(16*message_len);
    unsigned char *in[16];
    unsigned char buff[16][32];
    unsigned char *out[16];
    for (int i = 0; i<16; i++) {
        out[i] = buff[i];
    }
    for (size_t delta = 1; delta <= message_len; delta++) {
            // Delta is here to stress out the incremental update feature

            // If we're in fast mode, only test out some of the possible
            // deltas.
        if (fast_flag && delta < message_len && delta%11 != 0) continue;

        for (int lane = 0; lane < 16; lane++) {
            for (int i = 0; i<16; i++) {
                in[i] = &mem[i * message_len];
            }

            //
            // Insert the message into the selected lane; random data for the
            // other lanes
            for (int j = 0; j < 16; j++) {
                for (size_t k = 0; k < message_len; k++) {
                   if (j == lane) {
                      in[j][k] = message[k];
                   } else {   
                      in[j][k] = garbage();
                   }
                }
            }
    
            // Hash it
            slh_dsa::SHA256_16x_CTX ctx;
            for (size_t j=0; j<=message_len; j+=delta) {
                size_t this_len = message_len - j;
                if (this_len > delta) this_len = delta;
                ctx.update(in, this_len);
                for (int k = 0; k<16; k++) {  // Update the pointers
                    in[k] += this_len;
                }
            }
            ctx.final(out);
    
            // Check if the selected lane came up with the right answer
            if (0 != memcmp( out[lane], expected_hash, 32 )) {
                // The hash we got was wrong
                return false;
            }
        }
    }

    if (message_len > 64) {
        // Also test out the start-from-precomputed interface
        slh_dsa::SHA256_CTX sha256_ctx;
        sha256_ctx.init();
        sha256_ctx.update(message, 64);
        slh_dsa::sha256_state precompute;
        sha256_ctx.export_intermediate(precompute);

        for (int i = 0; i<16; i++) {
            in[i] = &mem[i * message_len];
        }
        for (int lane=0; lane<16; lane++) {
            //
            // Insert the message into the selected lane; random data for the
            // other lanes
            for (int j = 0; j < 16; j++) {
                for (size_t k = 0; k < message_len-64; k++) {
                   if (j == lane) {
                      in[j][k] = message[k+64];
                   } else {   
                      in[j][k] = garbage();
                   }
                }
            }

            slh_dsa::SHA256_16x_CTX ctx(precompute, 1);
            ctx.update(in, message_len-64);
            ctx.final(out);
    
            // Check if the selected lane came up with the right answer
            if (0 != memcmp( out[lane], expected_hash, 32 )) {
                // The hash we got was wrong
                return false;
            }
        }
    }

    return true;
}

struct {
    unsigned char hash[32];
} sha256_testvector[256] = {
#include "sha256_testvector.h"
};

static bool test_sha256_avx512(bool fast_flag) {
    /* Do the standard abc test vector */
    unsigned char test_vector1[] = { 'a', 'b', 'c' };
    size_t len_test_vector1 = 3;
    unsigned char expected_result1[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    if (!test_sha256( test_vector1, len_test_vector1, expected_result1, fast_flag )) {
        return false;
    }

    /* Now go through and test all lengths from 1 to 256 */
    /* We use this n, n+1, n+2, ..., 2n-1 pattern to make the precompute */
    /* test a bit more relevant, so each preimage is different */
    unsigned char input[256];
    for (int i=1; i<=256; i++) {
        for (int j=0; j<i; j++) input[j] = i+j;
        if (!test_sha256( input, i, sha256_testvector[i-1].hash, fast_flag )) {
            return false;
        }
    }

    return true;
}

//
// Our SHA-512 implementation does 8 SHA-512 hashes at once.  What we do is
// for each one of the 8 lanes, we insert the message, and for the other 7
// lanes, we insert random data.  Then, after the hash, we check if the output
// lane has the expected value (and we ignore the others because, well, random
// data)
static bool test_sha512( const unsigned char *message, size_t message_len, const unsigned char *expected_hash, bool fast_flag ) {
    auto mem = std::make_unique<unsigned char[]>(8*message_len);
    unsigned char *in[8];
    unsigned char buff[8][64];
    unsigned char *out[8];
    for (int i = 0; i<8; i++) {
        out[i] = buff[i];
    }
    for (size_t delta = 1; delta <= message_len; delta++) {
            // Delta is here to stress out the incremental update feature

            // If we're in fast mode, only test out some of the possible
            // deltas.
        if (fast_flag && delta < message_len && delta%11 != 0) continue;

        for (int lane = 0; lane < 8; lane++) {
            for (int i = 0; i<8; i++) {
                in[i] = &mem[i * message_len];
            }

            //
            // Insert the message into the selected lane; random data for the
            // other lanes
            for (int j = 0; j < 8; j++) {
                for (size_t k = 0; k < message_len; k++) {
                   if (j == lane) {
                      in[j][k] = message[k];
                   } else {   
                      in[j][k] = garbage();
                   }
                }
            }
    
            // Hash it
            slh_dsa::SHA512_8x_CTX ctx;
            for (size_t j=0; j<=message_len; j+=delta) {
                size_t this_len = message_len - j;
                if (this_len > delta) this_len = delta;
                ctx.update(in, this_len);
                for (int k = 0; k<8; k++) {  // Update the pointers
                    in[k] += this_len;
                }
            }
            ctx.final(out);
    
            // Check if the selected lane came up with the right answer
            if (0 != memcmp( out[lane], expected_hash, 64 )) {
                // The hash we got was wrong
                return false;
            }
        }
    }

    if (message_len > 128) {
        // Also test out the start-from-precomputed interface
        slh_dsa::SHA512_CTX sha512_ctx;
        sha512_ctx.init();
        sha512_ctx.update(message, 128);
        slh_dsa::sha512_state precompute;
        sha512_ctx.export_intermediate(precompute);

        for (int i = 0; i<8; i++) {
            in[i] = &mem[i * message_len];
        }
        for (int lane=0; lane<8; lane++) {
            //
            // Insert the message into the selected lane; random data for the
            // other lanes
            for (int j = 0; j < 8; j++) {
                for (size_t k = 0; k < message_len-128; k++) {
                   if (j == lane) {
                      in[j][k] = message[k+128];
                   } else {   
                      in[j][k] = garbage();
                   }
                }
            }

            slh_dsa::SHA512_8x_CTX ctx(precompute, 1);
            ctx.update(in, message_len-128);
            ctx.final(out);
    
            // Check if the selected lane came up with the right answer
            if (0 != memcmp( out[lane], expected_hash, 64 )) {
                // The hash we got was wrong
                return false;
            }
        }
    }

    return true;
}

struct {
    unsigned char hash[64];
} sha512_testvector[256] = {
#include "sha512_testvector.h"
};

static bool test_sha512_avx512(bool fast_flag) {
    /* Do the standard abc test vector */
    unsigned char test_vector1[] = { 'a', 'b', 'c' };
    size_t len_test_vector1 = 3;
    unsigned char expected_result1[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
        0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
        0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
        0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
        0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    };
    if (!test_sha512( test_vector1, len_test_vector1, expected_result1, fast_flag )) {
        return false;
    }

    /* Now go through and test all lengths from 1 to 256 */
    /* We use this n, n+1, n+2, ..., 2n-1 pattern to make the precompute */
    /* test a bit more relevant, so each preimage is different */
    unsigned char input[256];
    for (int i=1; i<=256; i++) {
        for (int j=0; j<i; j++) input[j] = i+j;
        if (!test_sha512( input, i, sha512_testvector[i-1].hash, fast_flag )) {
            return false;
        }
    }

    return true;
}

//
// Our SHAKE-256 implementation does 4 SHAKE hashes at once.  What we do is
// for each one of the 8 lanes, we insert the message, and for the other 7
// lanes, we insert random data.  Then, after the hash, we check if the output
// lane has the expected value (and we ignore the others because, well, random
// data)
static bool test_shake256( const unsigned char *message, size_t message_len, const unsigned char *expected_hash, size_t expected_hash_len, bool fast_flag ) {
    auto mem = std::make_unique<unsigned char[]>(8*message_len + 1);
    unsigned char *in[8];
    auto buff = std::make_unique<unsigned char[]>(8*expected_hash_len);
    unsigned char *out[8];
    for (int i = 0; i<8; i++) {
        out[i] = &buff[i * expected_hash_len];
    }
    for (size_t delta = 1; delta <= message_len || (message_len == 0 && delta == 1); delta++) {
            // Delta is here to stress out the incremental update feature

            // If we're in fast mode, only test out some of the possible
            // deltas.
        if (fast_flag && delta < message_len && delta%11 != 0) continue;

        for (int lane = 0; lane < 8; lane++) {
            for (int i = 0; i<8; i++) {
                in[i] = &mem[i * message_len];
            }

            //
            // Insert the message into the selected lane; random data for the
            // other lanes
            for (int j = 0; j < 8; j++) {
                for (size_t k = 0; k < message_len; k++) {
                   if (j == lane) {
                      in[j][k] = message[k];
                   } else {   
                      in[j][k] = garbage();
                   }
                }
            }
    
            // Hash it
            slh_dsa::SHAKE256_8x_CTX ctx;
            for (size_t j=0; j<=message_len; j+=delta) {
                size_t this_len = message_len - j;
                if (this_len > delta) this_len = delta;
                ctx.update(in, this_len);
                for (int k = 0; k<8; k++) {  // Update the pointers
                    in[k] += this_len;
                }
            }
            // Note: we don't test out incremental squeezing.  Our 
            // application doesn't use it, but a thorough test would check
            // it out anyways
            ctx.squeeze(out, expected_hash_len);
    
            // Check if the selected lane came up with the right answer
            if (0 != memcmp( out[lane], expected_hash, expected_hash_len )) {
                // The hash we got was wrong
                return false;
            }
        }
    }

    return true;
}

struct {
    const char *preimage;
    unsigned preimage_len;
    const char *output;
    unsigned output_len;
} shake256_testvector[] = {
#include "shake256_testvector.h"
};

static bool test_shake256_avx512(bool fast_flag) {
    /* Do a zero length test vector */
    /* From the nice test vector https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf */
    /* Not ideal, as all lanes will be doing the same thing, but we do have */
    /* intermediate states */
    unsigned char test_vector1[] = { 0 };
    size_t len_test_vector1 = 0;
    unsigned char expected_result1[] = {
0x46,0xB9,0xDD,0x2B,0x0B,0xA8,0x8D,0x13,0x23,0x3B,0x3F,0xEB,0x74,0x3E,0xEB,0x24,
0x3F,0xCD,0x52,0xEA,0x62,0xB8,0x1B,0x82,0xB5,0x0C,0x27,0x64,0x6E,0xD5,0x76,0x2F,
0xD7,0x5D,0xC4,0xDD,0xD8,0xC0,0xF2,0x00,0xCB,0x05,0x01,0x9D,0x67,0xB5,0x92,0xF6,
0xFC,0x82,0x1C,0x49,0x47,0x9A,0xB4,0x86,0x40,0x29,0x2E,0xAC,0xB3,0xB7,0xC4,0xBE,
0x14,0x1E,0x96,0x61,0x6F,0xB1,0x39,0x57,0x69,0x2C,0xC7,0xED,0xD0,0xB4,0x5A,0xE3,
0xDC,0x07,0x22,0x3C,0x8E,0x92,0x93,0x7B,0xEF,0x84,0xBC,0x0E,0xAB,0x86,0x28,0x53,
0x34,0x9E,0xC7,0x55,0x46,0xF5,0x8F,0xB7,0xC2,0x77,0x5C,0x38,0x46,0x2C,0x50,0x10,
0xD8,0x46,0xC1,0x85,0xC1,0x51,0x11,0xE5,0x95,0x52,0x2A,0x6B,0xCD,0x16,0xCF,0x86,
0xF3,0xD1,0x22,0x10,0x9E,0x3B,0x1F,0xDD,0x94,0x3B,0x6A,0xEC,0x46,0x8A,0x2D,0x62,
0x1A,0x7C,0x06,0xC6,0xA9,0x57,0xC6,0x2B,0x54,0xDA,0xFC,0x3B,0xE8,0x75,0x67,0xD6,
0x77,0x23,0x13,0x95,0xF6,0x14,0x72,0x93,0xB6,0x8C,0xEA,0xB7,0xA9,0xE0,0xC5,0x8D,
0x86,0x4E,0x8E,0xFD,0xE4,0xE1,0xB9,0xA4,0x6C,0xBE,0x85,0x47,0x13,0x67,0x2F,0x5C,
0xAA,0xAE,0x31,0x4E,0xD9,0x08,0x3D,0xAB,0x4B,0x09,0x9F,0x8E,0x30,0x0F,0x01,0xB8,
0x65,0x0F,0x1F,0x4B,0x1D,0x8F,0xCF,0x3F,0x3C,0xB5,0x3F,0xB8,0xE9,0xEB,0x2E,0xA2,
0x03,0xBD,0xC9,0x70,0xF5,0x0A,0xE5,0x54,0x28,0xA9,0x1F,0x7F,0x53,0xAC,0x26,0x6B,
0x28,0x41,0x9C,0x37,0x78,0xA1,0x5F,0xD2,0x48,0xD3,0x39,0xED,0xE7,0x85,0xFB,0x7F,
0x5A,0x1A,0xAA,0x96,0xD3,0x13,0xEA,0xCC,0x89,0x09,0x36,0xC1,0x73,0xCD,0xCD,0x0F,
0xAB,0x88,0x2C,0x45,0x75,0x5F,0xEB,0x3A,0xED,0x96,0xD4,0x77,0xFF,0x96,0x39,0x0B,
0xF9,0xA6,0x6D,0x13,0x68,0xB2,0x08,0xE2,0x1F,0x7C,0x10,0xD0,0x4A,0x3D,0xBD,0x4E,
0x36,0x06,0x33,0xE5,0xDB,0x4B,0x60,0x26,0x01,0xC1,0x4C,0xEA,0x73,0x7D,0xB3,0xDC,
0xF7,0x22,0x63,0x2C,0xC7,0x78,0x51,0xCB,0xDD,0xE2,0xAA,0xF0,0xA3,0x3A,0x07,0xB3,
0x73,0x44,0x5D,0xF4,0x90,0xCC,0x8F,0xC1,0xE4,0x16,0x0F,0xF1,0x18,0x37,0x8F,0x11,
0xF0,0x47,0x7D,0xE0,0x55,0xA8,0x1A,0x9E,0xDA,0x57,0xA4,0xA2,0xCF,0xB0,0xC8,0x39,
0x29,0xD3,0x10,0x91,0x2F,0x72,0x9E,0xC6,0xCF,0xA3,0x6C,0x6A,0xC6,0xA7,0x58,0x37,
0x14,0x30,0x45,0xD7,0x91,0xCC,0x85,0xEF,0xF5,0xB2,0x19,0x32,0xF2,0x38,0x61,0xBC,
0xF2,0x3A,0x52,0xB5,0xDA,0x67,0xEA,0xF7,0xBA,0xAE,0x0F,0x5F,0xB1,0x36,0x9D,0xB7,
0x8F,0x3A,0xC4,0x5F,0x8C,0x4A,0xC5,0x67,0x1D,0x85,0x73,0x5C,0xDD,0xDB,0x09,0xD2,
0xB1,0xE3,0x4A,0x1F,0xC0,0x66,0xFF,0x4A,0x16,0x2C,0xB2,0x63,0xD6,0x54,0x12,0x74,
0xAE,0x2F,0xCC,0x86,0x5F,0x61,0x8A,0xBE,0x27,0xC1,0x24,0xCD,0x8B,0x07,0x4C,0xCD,
0x51,0x63,0x01,0xB9,0x18,0x75,0x82,0x4D,0x09,0x95,0x8F,0x34,0x1E,0xF2,0x74,0xBD,
0xAB,0x0B,0xAE,0x31,0x63,0x39,0x89,0x43,0x04,0xE3,0x58,0x77,0xB0,0xC2,0x8A,0x9B,
0x1F,0xD1,0x66,0xC7,0x96,0xB9,0xCC,0x25,0x8A,0x06,0x4A,0x8F,0x57,0xE2,0x7F,0x2A,
    };
    if (!test_shake256( test_vector1, len_test_vector1, expected_result1, sizeof expected_result1, fast_flag )) {
        return false;
    }

    /* Now go through and test vectors from NIST */
    for (size_t i=0; i<sizeof shake256_testvector/sizeof *shake256_testvector; i++) {
        if (!test_shake256((const unsigned char *)shake256_testvector[i].preimage,
                           shake256_testvector[i].preimage_len,
                           (const unsigned char *)shake256_testvector[i].output,
                           shake256_testvector[i].output_len,
                           fast_flag)) {
            return false;
        }
    }

    return true;
}

bool test_avx512(bool fast_flag, enum noise_level noise) {
    if (noise == loud) {
        printf( " Testing AVX2-512 implementation of SHA-256\n" );
    }
    if (!test_sha256_avx512(fast_flag)) {
        printf( "  SHA-256 failed\n" );
        return false;
    }
    if (noise == loud) {
        printf( " Testing AVX2-512 implementation of SHA-512\n" );
    }
    if (!test_sha512_avx512(fast_flag)) {
        printf( "  SHA-512 failed\n" );
        return false;
    }
    if (noise == loud) {
        printf( " Testing AVX2-512 implementation of SHAKE-256\n" );
    }
    if (!test_shake256_avx512(fast_flag)) {
        printf( "  SHAKE-256 failed\n" );
        return false;
    }
    return true;
}
