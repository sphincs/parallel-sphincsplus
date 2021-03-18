/*
 * This file has support routines that compute multiple hashes at once
 */ 
#include <string.h>
#include "api.h"
#include "xn_internal.h"
#include "internal.h"

namespace sphincs_plus {

//
// This builds the Merkle tree, placing the computed root into root
// and (if idx_leaf is not ~0) the authentication path into sig
//
// Meaning of mode:
// 0x00 - Build the entire Merkle tree
// 0x01 - Build only the left side of the Merkle tree
// 0x03 - Build only the right side of the Merkle tree
void key::merkle_sign(uint8_t *sig, unsigned char *root,
                     addr_t wots_addr, addr_t tree_addr,
                     uint32_t idx_leaf, unsigned mode) {
    unsigned char *auth_path = sig ;
    addr_t tree_addrxn[max_track];
    int j;
    struct leaf_info_xn info;
    int num_track = this->num_track(); // Number of hashes we can compute at
                         //  once

    memset( tree_addrxn, 0, addr_bytes*num_track);
    memset( info.leaf_addr, 0, addr_bytes*num_track);
    memset( info.pk_addr, 0, addr_bytes*num_track);
    for (j=0; j<num_track; j++) {
        set_type(tree_addrxn[j], ADDR_TYPE_HASHTREE);
        set_type(info.leaf_addr[j], ADDR_TYPE_WOTS);
        set_type(info.pk_addr[j], ADDR_TYPE_WOTSPK);
        copy_subtree_addr(tree_addrxn[j], tree_addr);
        copy_subtree_addr(info.leaf_addr[j], wots_addr);
        copy_subtree_addr(info.pk_addr[j], wots_addr);
    }

    info.wots_sign_leaf = idx_leaf;

    // If we're building a half tree, then we reduce
    // the tree height we walk by one
    uint32_t walk_height = merkle_height() - (mode&1);

    // If we're building only the right tree, offset the
    // starting tree position to start in the middle
    uint32_t walk_offset = (mode&2) << (merkle_height() - 2);

    treehashxn(root, auth_path,
                idx_leaf, walk_offset,
                walk_height,
                &key::wots_gen_leafxn,
                tree_addrxn, &info);
}

void key::fors_sign(uint8_t *sig, unsigned char *root,
                     unsigned which_fors_tree, uint32_t idx_leaf,
                     addr_t fors_addr ) {
    addr_t fors_tree_addr_xn[max_track];
    struct fors_gen_leaf_info_xn fors_info;
    addr_t* fors_leaf_addr_xn = fors_info.leaf_addrx;
    uint32_t idx_offset;
    unsigned num_track = this->num_track(); // Number of hashes we can
                         //  compute in parallel

    memset( fors_tree_addr_xn, 0, addr_bytes * num_track );
    memset( fors_leaf_addr_xn, 0, addr_bytes * num_track );

    for (unsigned i=0; i<num_track; i++) {
        copy_keypair_addr(fors_tree_addr_xn[i], fors_addr);
        set_type(fors_tree_addr_xn[i], ADDR_TYPE_FORSTREE);
        copy_keypair_addr(fors_leaf_addr_xn[i], fors_addr);
        set_type(fors_leaf_addr_xn[i], ADDR_TYPE_FORSTREE);
    }

    idx_offset = which_fors_tree << t();

    /* Include the secret key part that produces the selected leaf node. */
    fors_info.revealed_idx = idx_leaf + idx_offset;
    fors_info.leaf_buffer = sig;
    sig += len_hash();

    /* Compute the authentication path for this leaf node. */
    treehashxn(root, sig,
                idx_leaf, idx_offset, t(),
                &key::fors_gen_leafxn,
                fors_tree_addr_xn, &fors_info);
}

//
// Generate a WOTS signature of the given message (which is n bytes long)
void key::wots_sign( unsigned char *sig, unsigned merkle_level,
                    uint64_t tree_idx, unsigned leaf_idx,
                    const unsigned char *message ) {
    unsigned n = len_hash();
    addr_t leaf_addr[max_track];
    unsigned digits = wots_digits();
    unsigned num_track = this->num_track(); // Number of hashes we can
                         // compute in parallel

    // Create the base values
    memset( leaf_addr, 0, num_track*addr_bytes );
    for (unsigned j=0; j<num_track; j++) {
        set_type(leaf_addr[j], ADDR_TYPE_WOTS);
        set_layer_addr(leaf_addr[j], merkle_level);
        set_tree_addr(leaf_addr[j], tree_idx);
        set_keypair_addr(leaf_addr[j], leaf_idx);
        set_hash_addr(leaf_addr[j], 0);
    }
    unsigned char *pointer[max_track];
    for (unsigned j=0; j<digits; j+=num_track) {
        unsigned char dummy_buffer[max_len_hash];
        for (unsigned k=0; k<num_track; k++) {
            set_chain_addr(leaf_addr[k], j+k);
            if (j+k < digits) {
                pointer[k] = sig + (j+k)*n;
            } else {
                pointer[k] = dummy_buffer;
	    }
	}
        prf_addr_xn(pointer, leaf_addr);
    }

    // Convert the message into a series of digits
    unsigned lengths[max_wots_digits];
    chain_lengths(lengths, message);

    // Form the instructions for the chain computation function
    struct digit d_array[max_wots_digits];
    for (unsigned i=0; i<digits; i++) {
        d_array[i].index = 0;   // All chains start at 0
        d_array[i].count = lengths[i];  // For chain i, compute up the given
                                // number of positions
    }

    // And advance all the digits as needed
    compute_chains( sig, d_array, leaf_addr );
}

/*
 * Generate the entire Merkle tree, computing the authentication path for
 * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 *
 * If leaf_idx == ~0, nothing is written to the authentication path buffer
 *
 * This expects tree_addrxn to be initialized to 8 parallel addr structures
 * for the Merkle tree nodes
 *
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 *
 * This works by using the standard Merkle tree building algorithm, except
 * that each 'node' tracked is actually track consecutive nodes in the real
 * tree.
 * When we combine two logical nodes ABCDEFGH and STUVWXYZ (for track=8), we
 * perform the H* operation on adjacent real nodes, forming the parent logical
 * node, in this case, * (AB)(CD)(EF)(GH)(ST)(UV)(WX)(YZ)
 *
 * When we get to the top log(num_track) levels of the real tree (where there
 * is only one logical node), we continue this operation log(num_track) more
 * times; the right most real node will by the actual root (and the other
 * num_track-1 nodes will be garbage).  We follow the same thash_xn logic so
 * that the 'extract authentication path components' part of the loop is still
 * executed (and to simplify the code somewhat)
 *
 * This currently assumes tree_height >= 3; I suspect that doing an adjusting
 * idx, addr_idx on the gen_leafxn call if tree_height < 3 would fix it; since
 * we don't actually use such short trees, I haven't bothered
 */
void key::treehashxn(unsigned char *root, unsigned char *auth_path,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (key::*gen_leafxn)(
                   unsigned char* /* Where to write the leaves */,
                   uint32_t idx, void *info),
                addr_t* tree_addrxn,
                void *info)
{
    unsigned n = len_hash();
    unsigned num_track = this->num_track();
    unsigned half_track = num_track/2;
    unsigned log_track = this->num_log_track();

    /* This is where we keep the intermediate nodes */
    unsigned char stack[max_track*max_merkle_tree_height*max_len_hash];
    uint32_t left_adj = 0, prev_left_adj = 0; /* When we're doing the top 3 */
        /* levels, the left-most part of the tree isn't at the beginning */
        /* of current[].  These give the offset of the actual start */

    uint32_t idx;
    uint32_t max_idx = (1 << (tree_height-log_track)) - 1;
    unsigned char current[max_track*max_len_hash];   // Current logical node

    // When we do the thash_xn below, our output buffer will always be
    // current and half of our input buffer will always be current
    unsigned char *out[max_track];
        // We will always thash into the current buffer
    for (unsigned j = 0; j < num_track; j++) out[j] = &current[j * n];
    unsigned char *in[max_track];
        // Set up the STUVWXYZ input side
    for (unsigned j = 0; j < half_track; j++) {
        in[j+half_track] = &current[j * 2 * n];
    }

    for (idx = 0;; idx++) {
        (this->*gen_leafxn)( current, num_track*idx + idx_offset, info );

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     /* The height we are in the Merkle tree */
        for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {

            /* Special processing if we're at the top of the tree */
            if (h >= tree_height - log_track) {
                if (h == tree_height) {
                    /* We hit the root; return it */
                    memcpy( root, &current[(num_track-1)*n], n );
                    return;
                }
                /* The tree indexing logic is a bit off in this case */
                /* Adjust it so that the left-most node of the part of */
                /* the tree that we're processing has index 0 */
                prev_left_adj = left_adj;
                left_adj = num_track - (1 << (tree_height - h - 1));
            }

            /* Check if we hit the top of the tree */
            if (h == tree_height) {
                /* We hit the root; return it */
                memcpy( root, &current[(num_track-1)*n], n );
                return;
            }
            
            /*
             * Check if one of the nodes we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((((internal_idx << log_track) ^ internal_leaf) & ~(num_track-1)) == 0) {
                memcpy( &auth_path[ h * n ],
                        &current[(((internal_leaf&(num_track-1))^1) + prev_left_adj) * n],
                        n );
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 8 nodes into the one root node in three
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node (or doing the top 3 levels) */
            /* Now combine the left and right logical nodes together */

            // Set the address of the node we're creating.
            internal_idx_offset >>= 1;
            for (unsigned j = 0; j < num_track; j++) {
                set_tree_height(tree_addrxn[j], h + 1);
                set_tree_index(tree_addrxn[j],
                     half_track * (internal_idx&~1) + j - left_adj + internal_idx_offset );
            }

	    // Set up the part of the input vector that's the left input
	    // That is, the ABCDEFGH side
            unsigned char *left = &stack[h * num_track * n];
	    for (unsigned j = 0; j < half_track; j++) {
                in[j] = &left[j * 2 * n];
            }

	    // And thash those bad boys pairwise
            thash_xn( out,
                      in,
                      2, tree_addrxn);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy( &stack[h * num_track * n], current, num_track * n);
    }
}

/*
 * This generates num_track sequential WOTS public keys
 */
void key::wots_gen_leafxn(unsigned char *dest,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_xn *info = static_cast<struct leaf_info_xn *>(v_info);
    addr_t* leaf_addr = info->leaf_addr;
    addr_t* pk_addr = info->pk_addr;
    int i, j, k;
    int wots_len = wots_bytes();
    unsigned char pk_buffer[ max_track * max_wots_bytes ];
    unsigned wots_offset = wots_len;
    unsigned char *buffer;
    int num_track = this->num_track();

    for (j = 0; j < num_track; j++) {
        set_keypair_addr( leaf_addr[j], leaf_idx + j );
        set_keypair_addr( pk_addr[j], leaf_idx + j );
    }

    int wots_digits = this->wots_digits();
    unsigned n = len_hash();

    for (i = 0, buffer = pk_buffer; i < wots_digits; i++, buffer += n) {
        unsigned char *chain_buffer[max_track];
        for (k=0; k<num_track; k++) chain_buffer[k] = buffer + k*wots_offset;

        /* Start with the secret seed */
        for (j = 0; j < num_track; j++) {
            set_chain_addr(leaf_addr[j], i);
            set_hash_addr(leaf_addr[j], 0);
        }
        prf_addr_xn(chain_buffer, leaf_addr);

        /* Iterate down the WOTS chain */
        for (k=0; k < wots_w-1; k++) {

            /* Iterate one step on all num_track chains */
            for (j = 0; j < num_track; j++) {
                set_hash_addr(leaf_addr[j], k);
            }
            f_xn(chain_buffer, chain_buffer, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    unsigned char *output_buffer[max_track];
    for (i=0; i<num_track; i++) output_buffer[i] = dest + i*n;
    unsigned char *input_buffer[max_track];
    for (i=0; i<num_track; i++) input_buffer[i] = pk_buffer + i*wots_offset;
    thash_xn(output_buffer,
            input_buffer,
            wots_digits, pk_addr);
}

/*
 * This generates num_track sequential FORS private keys
 * This also generates the revealed leaf if leaf_idx indicates that it
 * is the one being revealed
 */
void key::fors_gen_leafxn(unsigned char *leaf,
                   uint32_t leaf_idx, void *v_info) {
    struct fors_gen_leaf_info_xn *info =
                    static_cast<struct fors_gen_leaf_info_xn *>(v_info);
    unsigned n = len_hash();
    addr_t* fors_leaf_addrxn = info->leaf_addrx;
    unsigned num_track = this->num_track();

    /* Only set the parts that the caller doesn't set */
    for (unsigned j = 0; j < num_track; j++) {
        set_tree_index(fors_leaf_addrxn[j], leaf_idx + j);
    }

    // Generate the num_track private values
    unsigned char *pointer[max_track];
    for (unsigned j = 0; j < num_track; j++) {
        pointer[j] = leaf + j*n;
    }
    prf_addr_xn(pointer, fors_leaf_addrxn);

    // Check if one of the leaves we generated is the one that's supposed to
    // be revealed
    if (((leaf_idx ^ info->revealed_idx) & ~(num_track-1)) == 0) {
        // Found it - copy it out
        memcpy( info->leaf_buffer, leaf + (info->revealed_idx & (num_track-1))*n, n );
    }

    // Convert the num_track private values into the corresponding public
    // values (the ones at the bottom of the FORS tree)
    unsigned char *leaves[max_track];
    for (unsigned j = 0; j < num_track; j++) leaves[j] = leaf + j*n;
    f_xn(leaves, leaves, fors_leaf_addrxn);
}

} /* namespace sphincs_plus */
