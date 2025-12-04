#ifndef SHA256AVX512_H_
#define SHA256AVX512_H_
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

class SHA256_16x_CTX {
    __m512i s[8];
    unsigned char msgblocks[16*64];
    int datalen;
    unsigned long long msglen;
    void transform(const unsigned char *data);
public:
    void init_from_intermediate(uint32_t *s, unsigned long long msglen);
    void init(void);
    void update(unsigned char *d[16], unsigned long long len);
    void final(unsigned char *out[16]);
};



} /* namespace slh_dsa */

#endif /* SHA256AVX512_H_ */
