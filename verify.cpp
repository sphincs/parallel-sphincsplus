///
/// \file verify.cpp
/// \brief This is the module that verifies an SLH-DSA signature
///
/// There's not a great deal of advantage of this over the reference code
/// (except for our support for multiple parameter sets simultaneously),
/// however this package would feel incomplete if we didn't provide it
///
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "internal.h"

namespace slh_dsa {

//
// This verifies a signature
success_flag key::verify( 
            const unsigned char *signature, size_t len_signature,
            const void *message, size_t len_message,
	    const void *context, size_t len_context) {
    return verify_internal(signature, len_signature,
		           0x00,    // We're not prehashing
		           context, len_context,
			   0, 0,    // No hash OID
			   message, len_message);
}

//
// One note about this logic: this really does process a signature in
// order (mostly); however our geo logic has the signature components all
// parsed out, so we use that, rather than stepping through the signature
success_flag key::verify_internal(
            const unsigned char *signature, size_t len_signature,
	    unsigned char domain_separator_byte,
	    const void *context, size_t len_context,
	    const void *oid, size_t len_oid,
            const void *message, size_t len_message) {
    // Make sure this key has the public key loaded
    if (!have_public_key) return false;

    if (len_context > 255) return false;

    size_t n = len_hash();

    // Step 1: lay out where the various components of the signature are
    struct signature_geometry geo;

    size_t signature_length = initialize_geometry(geo);

    // Now, check if the buffer we were given is long enough
    if (signature_length > len_signature) {
        return failure;   // Signature not long enough
    }

    // Step 2 - hash the message
    hash_message( geo, &signature[ geo.randomness_offset ],
             domain_separator_byte, context, len_context, oid, len_oid,
             message, len_message );

    // Step 3 - walk up the FORS trees to generate the FORS root
    // This logic would fit nicely in xn_hash, except that something
    // not needing a verifier wouldn't use it, so we just do it here
    unsigned char fors_node[ max_fors_trees * max_len_hash ];
    for (unsigned i=0; i<k(); i++) {
        memcpy(&fors_node[i * n], signature + geo.fors_offset[i], n );
    }
    uint track = num_track();
    addr_t addrx[ max_track ];
    memset( addrx, 0, track * addr_bytes );
    for (int i=0; i<8;i++) {
        set_tree_addr(addrx[i], geo.idx_tree);
        set_keypair_addr(addrx[i], geo.idx_leaf);
        set_type(addrx[i], ADDR_TYPE_FORSTREE);
    }
    for (unsigned i=0; i<k(); i+=track) {
        unsigned this_track = k() - i;  // Number of tracks we're processing
                                        // this iteration
        if (this_track > track) this_track = track;
        unsigned char *out[max_track];
        for (unsigned j=0; j<this_track; j++) {
            out[j] = &fors_node[(i+j)*n];
        }
            // Point the unused tracks somewhere harmless
        unsigned char dummy[max_len_hash];
        for (unsigned j=this_track; j<track; j++) {
            out[j] = dummy;
        }
        unsigned char *in[max_track];
        unsigned char in_buffer[max_track][2*max_len_hash];
        for (unsigned j=0; j<track; j++) {
            in[j] = in_buffer[j];
        }

        uint32_t fors_index[max_track];
        for (unsigned j=0; j<track; j++) {
            fors_index[j] = geo.fors[i+j] + ((i+j)<<t());
        }

        // Do the initial hash of the revealed FORS leaves
        for (unsigned k=0; k<this_track; k++) {
            set_tree_height(addrx[k], 0);
            set_tree_index(addrx[k], fors_index[k] );
        }
        f_xn(out, out, addrx);

        for (unsigned j=0; j<t(); j++) {
            for (unsigned k=0; k<this_track; k++) {
                 // Set up in_buffer
                 int bit = (fors_index[k] >> j) & 1;
                 memcpy( &in[k][(1-bit)*n ],
                         signature + geo.fors_offset[i+k] + (j+1)*n, n );
                 memcpy( &in[k][(bit  )*n ], out[k], n );

                 // Set up tree_addrxn
                 set_tree_height(addrx[k], j+1);
                 set_tree_index(addrx[k], fors_index[k] >> (j+1) );
            }
            thash_xn( out, in, 2, addrx);
        }
    }

    // Now hash all the fors tree roots together
    unsigned char current[max_len_hash];
    addr_t fors_pk_addr = { 0 };
    set_tree_addr(fors_pk_addr, geo.idx_tree);
    set_keypair_addr(fors_pk_addr, geo.idx_leaf);
    set_type(fors_pk_addr, ADDR_TYPE_FORSPK);
    thash(current, fors_node, k(), fors_pk_addr);

    // Now set up through each Merkle tree
    uint64_t tree_idx = geo.idx_tree;
    uint32_t leaf_idx = geo.idx_leaf;
    for (unsigned tree=0; tree<d(); tree++) {
        // Convert the hash into wots digits
        unsigned lengths[max_wots_digits];
        chain_lengths(lengths, current);

        // Form the instructions for the chain computation function
        struct digit d_array[max_wots_digits];
        for (unsigned i=0; i<wots_digits(); i++) {
            d_array[i].index = lengths[i];   // Chains start at the wots digit
            d_array[i].count = (wots_w-1)-lengths[i];  // Each chain goes up
                                             // to digit wots_w-1
        }

        addr_t wots_addr[max_track];
        memset(wots_addr, 0, track*32);
        for (unsigned j=0; j<track; j++) {
            set_type(wots_addr[j], ADDR_TYPE_WOTS);
            set_layer_addr(wots_addr[j], tree);
            set_tree_addr(wots_addr[j], tree_idx);
            set_keypair_addr(wots_addr[j], leaf_idx);
        }

        unsigned char wots_nodes[ max_wots_digits * max_len_hash ];
        memcpy( wots_nodes, signature + geo.wots[tree], wots_digits() * n );

        // And advance all the digits as specified
        compute_chains( wots_nodes, d_array, wots_addr );

        // And hash all the tops of the WOTS chains into a single value
        addr_t wots_pk_addr = { 0 };
        set_type(wots_pk_addr, ADDR_TYPE_WOTSPK);
        set_layer_addr(wots_pk_addr, tree);
        set_tree_addr(wots_pk_addr, tree_idx);
        set_keypair_addr(wots_pk_addr, leaf_idx);
        thash(current, wots_nodes, wots_digits(), wots_pk_addr);

        // And climb up the Merkle tree
        addr_t merkle_addr = { 0 };
        set_type(merkle_addr, ADDR_TYPE_HASHTREE);
        set_layer_addr(merkle_addr, tree);
        set_tree_addr(merkle_addr, tree_idx);
        uint32_t tree_index = leaf_idx;
        const unsigned char *merkle_sig = signature + geo.merkle[tree];
        for (unsigned j=0; j<merkle_height(); j++) {
            unsigned char siblings[2*max_len_hash];
            unsigned bit = tree_index & 1;
            tree_index >>= 1;
            memcpy( &siblings[(1-bit)*n], merkle_sig, n );
            memcpy( &siblings[ bit   *n], current, n );
            merkle_sig += n;

            set_tree_height(merkle_addr, j+1);
            set_tree_index(merkle_addr, tree_index);
            thash(current, siblings, 2, merkle_addr);
        }

        leaf_idx = tree_idx & ((1<<merkle_height())-1);
        tree_idx >>= merkle_height();
    }

    // We win if the final hash matches the value in the public key
    if (0 == memcmp( current, get_root(), n)) {
        // Sweet success
        return success;
    } else {
        // Nope - signature did not verify
        return failure;
    }
}

}  /* namespace slh_dsa */
