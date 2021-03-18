#include <string.h>
#include <stdint.h>
#include "api.h"
#include "internal.h"

namespace sphincs_plus {

//
// This lays out where things are within a signature
size_t key::initialize_geometry(struct signature_geometry& geo) {
    size_t n = len_hash();

    size_t offset = 0;
    geo.randomness_offset = offset; offset += n;  // Randomness comes first
    for (unsigned i=0; i<k(); i++) {   // Then comes the various FORS trees
        geo.fors_offset[i] = offset; offset += (t() + 1) * n;
    }
    for (unsigned i=0; i<d(); i++) {   // Then comes the Merkle signatures
        // We generate the WOTS and Merkle signatures separately,
        // hence we track each one individually
        geo.wots[i] = offset; offset += wots_digits() * n;
        geo.merkle[i] = offset; offset += merkle_height() * n;
    }
    return offset;
}

class bit_extract {
    unsigned char *p;
    size_t len;    // Number of bytes remaining
    unsigned bits_in_byte; // Number of bits remaining in the current byte
public:
    bit_extract( unsigned char *input, size_t input_len ) {
        p = input; len = input_len; bits_in_byte = 8;
    }
    int extract_bits(unsigned bits) {
        unsigned r = 0;
        unsigned count_bits = 0;
        while (bits >= bits_in_byte) {
            r |= *p++ << count_bits;
            count_bits += bits_in_byte;
            bits -= bits_in_byte;
            bits_in_byte = 8;
        }
        if (bits > 0) {
            unsigned mask = (1 << bits) - 1;
            r += (*p & mask) << count_bits;
            *p >>= bits;
            bits_in_byte -= bits;
        }
        return r;
    }
    uint64_t extract_int(unsigned bits) {
        int bytes = (bits + 7) / 8;  // Number of bytes to extract
        uint64_t r = bytes_to_ull(p, bytes);
        p += bytes;
        bits_in_byte = 8;
        return r & ((~(uint64_t)0) >> (64 - bits));
    }
    void round(void) { if (bits_in_byte != 8) {
                           p++; len--; bits_in_byte = 8; } }
};

//
// This converts a message (and randomness) into the FORS/Merkle indices
void key::hash_message(struct signature_geometry& geo,
           const unsigned char *r, 
           const unsigned char *message, size_t len_message ) {

    unsigned char msg_hash[ max_len_h_msg ];

        // This is the number of bytes of h_msg output we'll need
    size_t len_h = (k()*t() + 7)/8;  // For the FORS leafs
    len_h += (h() - merkle_height() + 7)/8; // For the index of the bottom
                                     //  Merkle tree
    len_h += (merkle_height() + 7)/8; // For the leaf of the bottom Merkle

    h_msg( msg_hash, len_h, r, message, len_message );

    /* Now, parse that output into the individual values */
    bit_extract bit( msg_hash, len_h );

    /* The first k*a bits are the digits of the FORS trees */
    /* Note that the byte ordering is reversed; that's what the Sphincs+ */
    /* reference code does */
    for (unsigned i=0; i<k(); i++) {
        geo.fors[i] = bit.extract_bits( t() );
    }
    /* We step to the next byte boundery for the next output */
    bit.round();

    /* The next bits specify which bottom level Merkle tree we're in */
    geo.idx_tree = bit.extract_int( h() - merkle_height() );

    bit.round();
    /* The next bits specify which leaf of the bottom level tree we're in */
    geo.idx_leaf = bit.extract_int( merkle_height() );
}

}  /* namespace sphincs_plus */
