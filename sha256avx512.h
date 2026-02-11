#ifndef SHA256AVX512_H_
#define SHA256AVX512_H_
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

///
/// This is the class that allows us to compute 16 SHA-256 hashes in parallel
class SHA256_16x_CTX {
    __m512i s[8];                     //<! The SHA-256 state (in AVX format)
    unsigned char msgblocks[16*64];   //<! The message blocks that haven't
                                      //<! been compressed yet.  Each lane
                                      //<! owns a 64 byte contiguous segment
    int datalen;                      //<! How much data is in msgblocks
                                      //<! (per lane)
    unsigned long long msglen;        //<! The amount of data hashed, in bits
                                      //<! Does not include what's in msgblocks
    void transform(const unsigned char *data); //<! Perform a hash compression
                                      //<! operation
public:
    /// Create a 16x SHA-256 hasher, and initialize all lanes to empty
    SHA256_16x_CTX(void);

    /// Create a 16x SHA-256 hasher, and initialize all lanes to the
    /// given SHA-256 state (which is the state extracted from a SHA-256
    /// hash after hashing a multiple of 64 bytes of image);  num_blocks
    /// is the number of blocks that were in the prehash
    SHA256_16x_CTX(uint32_t *s, unsigned num_blocks);

    /// Add 16 new sections to the 16 messages being hashed by the 16
    /// different lanes
    void update(unsigned char *d[16], unsigned long long len);

    /// Finalize all 16 hashes and output them to the 16 different out buffers
    void final(unsigned char *out[16]);
};

} /* namespace slh_dsa */

#endif /* SHA256AVX512_H_ */
