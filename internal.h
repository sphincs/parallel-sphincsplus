#if !defined( INTERNAL_H_ )
#define INTERNAL_H_

/// \file internal.h
/// \brief Definitions used internally for the fast Sphincs+ implementation
/// That is, the ones that don't need to be mentioned within api.h
//
#include <stdint.h>

namespace sphincs_plus {

// Various constants that are used internally (but needn't be published in api.h)
const int wots_w = 16;      //<! All parameter sets have w=16
const int max_len_hash = 32; //<! The largest len_hash we ever have
const int max_fors_trees = 35; //<! The maximum number of FORS trees we have
                           //<! That's for the 256F parameter set
const int max_merkle_tree_height = 14; //<! The deepest tree we ever have
                           //<! That's the FORS trees within 192S and 256S
const int max_merkle_tree = 22; //<! The maximum number of Merkle trees we have
                           //<! That's for the 128F and 192F parameter sets
const int max_len_h_msg = 49; //<! The maximum number of bytes we need from
                           //<! h_msg; for 256F, that's 40 bytes for the FORS
                           //<! trees, 8 bytes for which bottom Merkle tree
			   //<! and 1 byte for the leaf of the bottom tree
const int max_wots_digits = 67; //<! Maximum number of digits
const int max_wots_bytes = max_len_hash * max_wots_digits; //<! The maximum
                           //<! size of a WOTS+ value
const int addr_bytes = 32; //<! Standard addr structures are 32 bytes lon
const int sha256_addr_bytes = 22; //<! SHA256 uses a shortened addr structure
                                  //<! that's 22 bytes long
const int sha256_output_size = 32; //<! The size of an untruncated SHA256 output
const int sha256_block_size = 64; //<! SHA256 processes things in 64 byte chunks
const int max_mgf1_input = max_len_hash + 32; //<! The maximum seed size for
                            //<! an MGF1 input.  32 is the size of an addr
const unsigned max_track = 8; //<! The maximum number of hashes we can do in
                            //<! parallel (on a single thread) is 8

const unsigned default_thread = 4; //<! If the application doesn't tell us
                            //<! otherwise, try to use 4 threads
const unsigned max_thread = 16; //<! No matter what the application says,
                            //<! don't use more than 16 threads

const bool default_detect_fault = false; //<! Turn off fault detected by
                            //<! default (it's expensive)

//<! Offsets of objects within a private key (figure 12 of the Sphincs+ spec)
//<! These are implicitly multiplied by n to get the byte offset
enum {
    PRIVKEY_SECRETSEED_OFFSET = 0, //<! Offset of the secret seed
    PRIVKEY_PRF_OFFSET = 1,        //<! Offset of the secret prf
    PRIVKEY_PUBLICKEY_OFFSET = 2,  //<! The public key starts at offset 2*n
    PRIVKEY_PUBLICSEED_OFFSET = 2, //<! Offset of the public seed
    PRIVKEY_ROOT_OFFSET = 3,       //<! Offset of the top level Merkle root
};
const unsigned LEN_PRIVKEY = 4;   //<! Length of a private key
                                  //<! Implicitly times n
const unsigned LEN_PUBKEY = 2;    //<! Length of a public key
                                  //<! Implicitly times n


// Interface to the compute_chains routine
//
/// This is the structure used to inform compute_chains how far to advance
/// each digit (and the index to use to start with)
struct digit {
    union {
        int count;   //<! Number of times to increment this digit
        int pointer; //<! Link to the next digit on the list
    };               //<! Yes, I'm aware they're the same type
                     //<! but they mean different things
    int index;       // <!Starting index for this digit
};

// Internal routines to convert between byte strings and integers
//
/// Convert an integer into a big-endian byte string
/// @param[out] out Where to place the big-endian byte string
/// @param[in] outlen The number of bytes to write
/// @param[in] in The value to write
void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);

/// Convert an integer into a 4 byte big-endian byte string
/// @param[out] out Where to place the big-endian byte string
/// @param[in] in The value to write
void u32_to_bytes(unsigned char *out, uint32_t in);

/// Convert a big-endian byte string into an integer
/// @param[in] in The bigendian byte string
/// @param[in] inlen The length of the strig
/// \return The value of the integer
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

/// Erase the buffer.  Equivalent to memset( buffer, 0, len_buffer ), except
/// that it is guarranteed that the optimizer will not decide to remove it
/// as unnecessary (which the optimizer might decide because the object being
/// cleared will be freed anyways)
/// @param[out] buffer Area to clear
/// @param[in] len_buffer Number of bytes to clear
void zeroize(void *buffer, size_t len_buffer);

/// This structure holds both the offsets of the various fields within a
/// signature, and also the details of which FORS/WOTS leaves are revealed
/// (which depends on the message)
struct signature_geometry {
    size_t randomness_offset;   //<! Where the randomness R value is
    size_t fors_offset[max_fors_trees]; //<! Where each FORS tree is 
    size_t wots[max_merkle_tree]; //<! Where each WOTS signature is 
    size_t merkle[max_merkle_tree]; //<! Where each Merkle auth path is 

    unsigned fors[ max_fors_trees ]; //<! Which FORS leafs are we revealing
    uint64_t idx_tree;          //<! Which bottom Merkle tree are we using
    unsigned idx_leaf;          //<! Which leaf of the bottom tree are we using
};

}

#endif /* INTERNAL_H_ */
