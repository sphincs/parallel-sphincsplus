#ifndef SHA512AVX512_H
#define SHA512AVX512_H
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
                                    //<! Does not include what's msgblocks
    void transform(const unsigned char *data); //<! Perform a hash compression
                                    //<! operation
public:
    void init(void);
    void init_frombytes(uint64_t *s, unsigned long long msglen);
    void update(unsigned char **in, unsigned long long len);
    void final(unsigned char **out);
};

} /* slh_dsa */

#endif /* SHA512AVX512_H */
