#include <stdint.h>
#include <string.h>

#include "api.h"
#include "internal.h"

/// \file address.cpp
/// \brief This contains the accessor functions for the addr_t fields
// at least, the ones that were complicated enough not to inline

namespace slh_dsa {

//
// Specify which Merkle tree within the level (the "tree address") we're working on
void key::set_tree_addr(addr_t addr, uint64_t tree)
{
    ull_to_bytes(&addr[offset_tree], 8, tree );
}

//
// Copy the layer and tree fields of the address structure.  This is used
// when we're doing multiple types of hashes within the same Merkle tree
void key::copy_subtree_addr(addr_t out, const addr_t in)
{
    memcpy( out, in, offset_tree+8 );
}

/* These functions are used for OTS addresses. */

//
// Specify which Merkle leaf we're working on; that is, which OTS keypair
// we're talking about.
void key::set_keypair_addr(addr_t addr, uint32_t keypair)
{
    ((unsigned char *)addr)[offset_kp_addr2] = keypair >> 8;
    ((unsigned char *)addr)[offset_kp_addr1] = keypair;
}

//
// Copy the layer, tree and keypair fields of the address structure.  This is
// used when we're doing multiple things within the same OTS keypair
void key::copy_keypair_addr(addr_t out, const addr_t in)
{
    memcpy( out, in, offset_tree+8 );
    out[offset_kp_addr2] = in[offset_kp_addr2];
    out[offset_kp_addr1] = in[offset_kp_addr1];
}

//
// Specify the distance from the left edge of the node in the Merkle/FORS tree
// (the tree index)
void key::set_tree_index(addr_t addr, uint32_t tree_index)
{
    u32_to_bytes(&addr[offset_tree_index], tree_index );
}

} /* namespace slh_dsa */
