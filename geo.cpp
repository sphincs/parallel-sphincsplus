#include <string.h>
#include <stdint.h>
#include "api.h"
#include "internal.h"

/// \file geo.cpp
/// \brief This contains hash the message into the fields used by SLH-DSA,
/// as well as to initialize the fixed fields in the geo structure

namespace slh_dsa {

/// This lays out where things are within a signature
/// That is, the offsets where the various FORS, WOTS+ and Merkle tree
/// authentication paths occur within the signature
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


///
/// This converts a message (and randomness) into the FORS/Merkle indices
void key::hash_message(struct signature_geometry& geo,
           const unsigned char *r,
           unsigned char domain_separator_byte,
           const void *context, size_t len_context,
           const void *oid, size_t len_oid,
           const void *message, size_t len_message ) {

    unsigned char msg_hash[ max_len_h_msg ];

        // This is the number of bytes of h_msg output we'll need
    size_t len_h = (k()*t() + 7)/8;  // For the FORS leafs
    len_h += (h() - merkle_height() + 7)/8; // For the index of the bottom
                                     //  Merkle tree
    len_h += (merkle_height() + 7)/8; // For the leaf of the bottom Merkle

    h_msg( msg_hash, len_h, r, domain_separator_byte, context,
	   len_context, oid, len_oid, message, len_message );

    /* Now, parse that output into the individual values */
    bit_extract bit( msg_hash, len_h );

    /* The first k*a bits are the digits of the FORS trees */
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

}  /* namespace slh_dsa */
