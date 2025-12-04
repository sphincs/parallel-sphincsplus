#include "api.h"

namespace slh_dsa {

// This returns true if we can use AVX-512F instructions on this CPU
bool check_avx512(void) {
    unsigned a, b, c, d;

    // Check for support of AVX-512
    a = 7;
    c = 0;
    asm volatile("cpuid"
                 : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                 : "a"(a), "c"(c)
    );
    if (b & (1 << 16)) {  // bit 16 of b is the avx512-f support
        return true;
    } else {
        return false;
    }
} 

} /* namespace slh_dsa */
