#if !defined(MGF1_8X_H_)
#define MGF1_8X_H_

#include "internal.h"
#include "immintrin.h"

namespace sphincs_plus {

class mgf1_8x {
    unsigned char state[8][max_mgf1_input+4];
    unsigned int state_len;
    unsigned int next_index;
    unsigned char output_index;
    union {
        __m256i output_buffer[8][ sha256_output_size / sizeof(__m256i) ];
        unsigned char char_output_buffer[8][ sha256_output_size ];
    };
public:
    mgf1_8x( unsigned char **seed, unsigned seed_len );
    void output( unsigned char **buffer, unsigned len_ouptut );
};

} /* namespace sphincs_plus */

#endif /* MGF1_8X_H_ */
