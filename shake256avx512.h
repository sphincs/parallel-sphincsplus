#ifndef SHAKE256AVX512_H_
#define SHAKE256AVX512_H_

#include "immintrin.h"

namespace slh_dsa {

class SHAKE256_8x_CTX {
    static const unsigned rate = 1088/8; /* The rate for SHAKE-256, in bytes */
    static const unsigned capacity = 8; /* The capacity, in 64 bit words */
    unsigned char s[8][rate]; /* In this representation, each lane has */
                      /* its own rate portion of the array as a */
                      /* continguous byte string */
    __m512i cap[capacity]; /* We place the capacity here */
                      /* It never gets involved in storing or squeezing */
                      /* so we can keep it in AVX-512 format */
    
    unsigned cur;     /* Where in the rate we are for absorbing and */
                      /* squeezing */
    int initial;      /* 1 -> we haven't permuted yet */
                      /*      If we haven't permuted, we haven't */
                      /*      initialized the elements cur and up, as */
                      /*      well as cap */
    enum { absorbing, squeezing } phase;
    void reset_initial(void);
    void permute(void);  /* All the magic is here */
public:
    void init(void);
    void update(unsigned char *d[8], unsigned len);
    void squeeze(unsigned char *out[8], unsigned len);
};  

} /* namespace slh_dsa */
 
#endif
