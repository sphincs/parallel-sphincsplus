#if !defined(SHA256_H_)
#define SHA256_H_

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

namespace sphincs_plus {

typedef uint32_t sha256_state[8];   // The core SHA256 state
                                    // Only valid after we have just
				    // completed a compression operation
				    // and does not track the count

class SHA256_CTX {
    sha256_state h;                 // State
    uint64_t count;                 // Number of bits processed so far
    unsigned num;                   // Number of bytes within the below
                                    // buffer
    unsigned char data[sha256_block_size]; // Input buffer.  This is in
                                    // byte vector format
    void compress(const void *buffer);
public:
    void init(void);
    void init_from_intermediate(const sha256_state init, unsigned int count);
    void update(const void *arc, uint64_t count);
    void final(unsigned char *digest);
    void export_intermediate(sha256_state intermedate);
    void zeroize(void) { sphincs_plus::zeroize( this, sizeof *this ); }
};

class mgf1 {
    unsigned char state[max_mgf1_input+4];
    unsigned int state_len;
    unsigned int next_index;
    unsigned char output_index;
    unsigned char output_buffer[ sha256_output_size ];
public:
    mgf1( const unsigned char *seed, unsigned seed_len );
    void output( unsigned char *buffer, unsigned len_ouptut );
};

} /* namespace sphincs_plus */

#endif /* SHA256_H_ */
