#ifndef SHA512AVX_H
#define SHA512AVX_H
#include <stdint.h>
#include "immintrin.h"

namespace slh_dsa {

class SHA512_8x_CTX {
    __m512i s[8];
    unsigned char msgblocks[8*128];
    int datalen;
    unsigned long long msglen;
    void transform(const unsigned char *data);
public:
    void init_frombytes(uint64_t *s, unsigned long long msglen);
    void init(void);
    void update(unsigned char **in, unsigned long long len);
    void final(unsigned char **out);
};

} /* slh_dsa */

#endif
