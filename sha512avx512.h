#ifndef SHA512AVX512_H_
#define SHA512AVX512_H_
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

///
/// This is the class that allows us to compute 8 SHA-512 hashes in parallel
class SHA512_8x_CTX {
    __m512i s[8];                   //<! The SHA-512 state (in AVX format)
    unsigned char msgblocks[8*128]; //<! The message blocks that haven't
                                    //<! been compressed yet.  Each lane
                                    //<! owns a 128 byte contiguous segment
    int datalen;                    //<! How much data is in msgblocks
                                    //<! (per lane)
    unsigned long long msglen;      //<! The amount of data hashed, in bits
                                    //<! Does not include what's in msgblocks
    void transform(const unsigned char *data); //<! Perform a hash compression
                                    //<! operation
public:
    /// Create an 8x SHA-512 hashes, and initialize all lanes to empty
    SHA512_8x_CTX(void);

    /// Create an 8x SHA-512 hasher, and initialize all lanes to the
    /// given SHA-512 state (which is the state extracted from a SHA-512
    /// hash after hashing a multiple of 128 bytes of image);  num_blocks
    /// is the number of blocks that were in the prehash
    SHA512_8x_CTX(uint64_t *s, unsigned num_blocks);

    /// Add 8 new sections to the 8 messages being hashed by the 8
    /// different lanes
    void update(unsigned char **in, unsigned long long len);

    /// Finalize all 8 hashes and output them to the 8 different out buffers
    void final(unsigned char **out);
};

} /* slh_dsa */

#endif /* SHA512AVX512_H_ */
