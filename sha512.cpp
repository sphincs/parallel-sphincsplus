/*
 * SHA-512
 * Implementation derived from LibTomCrypt (Tom St Denis)
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

#include <string.h>
#include <stdint.h>
#include "sha512.h"

namespace slh_dsa {

static void put_bigendian( unsigned char *target, uint64_t value,
                           size_t bytes ) {
    int i;

    for (i = bytes-1; i >= 0; i--) {
        target[i] = value & 0xff;
        value >>= 8;
    }
}
    
static uint64_t get_bigendian( const unsigned char *source,
                                         size_t bytes ) {
    uint64_t result = 0;

    for (size_t i=0; i<bytes; i++) {
        result = 256 * result + (source[i] & 0xff);
    }

    return result;
}

const unsigned SHA512_S_SIZE = 8;
const unsigned SHA512_K_SIZE = 80;
const unsigned SHA512_FINALCOUNT_SIZE = 16;

static const uint64_t K[SHA512_K_SIZE] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/* Various logical functions */
static uint64_t ROR64c(uint64_t x, unsigned y) {
    return (x >> (y&63)) | (x << (64 - (y&63)));
}
static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return z ^ (x & (y ^ z));
}
static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return ((x | y) & z) | (x & y);
}
static uint64_t S(uint64_t x, unsigned n) {
    return ROR64c(x, n);
}
static uint64_t R(uint64_t x, unsigned n) {
    return x >> n;
}
static uint64_t Sigma0(uint64_t x) {
    return S(x, 28) ^ S(x, 34) ^ S(x, 39);
}
static uint64_t Sigma1(uint64_t x) {
    return S(x, 14) ^ S(x, 18) ^ S(x, 41);
}
static uint64_t Gamma0(uint64_t x) {
    return S(x, 1) ^ S(x, 8) ^ R(x, 7);
}
static uint64_t Gamma1(uint64_t x) {
    return S(x, 19) ^ S(x, 61) ^ R(x, 6);
}

void SHA512_CTX::compress(const unsigned char *buf) {
    uint64_t S[SHA512_S_SIZE], W[SHA512_K_SIZE], t0, t1;

    /* copy state into S */
    for (unsigned i = 0; i < SHA512_S_SIZE; i++) {
        S[i] = h[i];
    }

    /* copy the state into 1024-bits into W[0..15] */
    for (unsigned i = 0; i < 16; i++ ) {
        W[i] =  get_bigendian( buf + (i << 3), 8 );
    }

    /* fill W[16..79] */
    for (unsigned i = 16; i < SHA512_K_SIZE; i++) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }        

    /* Compress */
    for (unsigned i = 0; i < SHA512_K_SIZE; i++) {
        t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t0;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t0 + t1;
    }


    /* feedback */
    for (unsigned i = 0; i < SHA512_S_SIZE; i++) {
        h[i] += S[i];
    }
}

void SHA512_CTX::init(void) {
    h[0] = 0x6a09e667f3bcc908ULL;
    h[1] = 0xbb67ae8584caa73bULL;
    h[2] = 0x3c6ef372fe94f82bULL;
    h[3] = 0xa54ff53a5f1d36f1ULL;
    h[4] = 0x510e527fade682d1ULL;
    h[5] = 0x9b05688c2b3e6c1fULL;
    h[6] = 0x1f83d9abfb41bd6bULL;
    h[7] = 0x5be0cd19137e2179ULL;

    count = 0;
    num = 0;
}

void SHA512_CTX::init_from_intermediate(const sha512_state init,
                                        unsigned int start_count) {
    memcpy( h, init, 8 * sizeof(uint64_t) );
    count = 8 * start_count;   // SHA512_CTX keeps a bit count
    num = 0;        // Intermediates always start at a block boundary
}

void SHA512_CTX::update(const void *src, size_t input_count) {
    count += (input_count << 3);

    while (input_count) {
        unsigned int this_step = 128 - num;
        if (this_step > input_count) this_step = input_count;
        memcpy( (unsigned char*)data + num, src, this_step);

        if (this_step + num < 128) {
            num += this_step;
            break;
        }

        src = (const unsigned char *)src + this_step;
        input_count -= this_step;
        num = 0;

        compress( data );
    }
}

/*
 * Add padding and return the message digest.
 */
void SHA512_CTX::final(unsigned char *digest) {
    unsigned int last, padn;
    unsigned char finalcount[SHA512_FINALCOUNT_SIZE];
    static unsigned char padding[128] = { 0x80 }; /* and the rest are zerso */

    put_bigendian( finalcount+0, 0, 8 );
    put_bigendian( finalcount+8, count, 8 );

    last = (size_t)( (count>>3) & 0x7F );
    padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

    update( padding, padn );
    update( finalcount, 16 );

    /* Note: need to rethink this loop should we ever support SHA512_224 */
    for (unsigned i=0; 8*i<sha512_output_size; i++) {
        put_bigendian( digest + 8*i, h[i], 8 );
    }
}

void SHA512_CTX::export_intermediate(sha512_state intermediate) {
    memcpy( intermediate, h, 8 * sizeof(uint64_t) );
}

} /* namespace slh_dsa */
