#ifndef SHAKE256AVX512_H_
#define SHAKE256AVX512_H_

#include <stdbool.h>
#include "immintrin.h"

namespace slh_dsa {

///
/// This is the class that allows us to compute 8 SHAKE-256 XOFs in parallel
class SHAKE256_8x_CTX {
    static const unsigned rate = 1088/8; //<! The rate for SHAKE-256, in bytes
    static const unsigned capacity = 8; //<! The capacity, in 64 bit words 
    unsigned char s[8][rate]; //<! In this representation, each lane has
                      //<! its own rate portion of the array as a
                      //<! continguous byte string
    __m512i cap[capacity]; //<! We place the capacity here
                      //<! It never gets involved in storing or squeezing
                      //<! so we can keep it in AVX-512 format
    
    unsigned cur;     //<! Where in the rate we are for absorbing and
                      //<! squeezing
    bool initial;     //<! true -> we haven't permuted yet
                      //<!      If we haven't permuted, we haven't
                      //<!      initialized the s elements cur and beyond,
                      //<!      as well as cap
    enum { absorbing, squeezing } phase; //<! are we absorbing or squeezing
                      //<! used to determine when we should finish up the
                      //<! absorbsion phase, add padding and do a final
                      //<! permutation
    void reset_initial(void); //<! Called when we've absorbed the first rate
                      //<! bytes - this prepares for the initial permutation
    void permute(void);  //<! Do the Keccak permutation.
                      //<! All the magic is here
public:
    /// Create an 8x SHAKE-256 hasher, and initialize all lanes to empty
    SHAKE256_8x_CTX(void);

    /// Absorb 8 new sections into the 8 SHAKE hashes being processed
    void update(unsigned char *d[8], unsigned len);

    /// Squeeze out the next output for each of the 8 lanes
    void squeeze(unsigned char *out[8], unsigned len);
};  

} /* namespace slh_dsa */
 
#endif
