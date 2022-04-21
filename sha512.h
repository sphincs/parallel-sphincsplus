#if !defined(SHA512_H_)
#define SHA512_H_

#include <stddef.h>
#include <stdint.h>
#include "internal.h"

/// \file sha512.h
/// \brief The definitions of the low level SHA512 classes

namespace sphincs_plus {

const unsigned sha512_block_size = 128; //<! SHA-512 processes data in
                                    //<! 128 byte chunks

typedef uint64_t sha512_state[8];   //<! The core SHA512 state
                                    //<! Used internally in the SHA512
                                    //<! implementation

/// The SHA512 context
class SHA512_CTX {
    sha512_state h;                 //<! State
    uint64_t count;                 //<! Number of bits processed so far
    unsigned num;                   //<! Number of bytes within the below
                                    //<! buffer
    unsigned char data[sha512_block_size]; //<! Input buffer.  This is in
                                    //<! byte vector format
    void compress(const unsigned char *buffer); //<! Perform the hash
                                    //<! compression operation
public:
    /// Initialize the context to the SHA-512 initial state
    void init(void);

    /// Add more data to the hash being computed
    /// @param[in] msg String to add to the hash
    /// @param[in] count Length of the string
    void update(const void *msg, size_t count);

    /// We're done adding data to the hash; now compute the final results
    /// @param[out] digest Where to place the hash
    void final(unsigned char *digest);

    /// Erase the hash state.  Used if we've hashed sensitive data and
    /// we need to free the hash object
    void zeroize(void) { sphincs_plus::zeroize( this, sizeof *this ); }
};

/// This is the object that implements the MGF1 arbitrary-sized output function
/// It is based on SHA-512
class mgf1_sha512 {
    unsigned char state[max_mgf1_input+4];
    unsigned int state_len;
    unsigned int next_index;
    unsigned char output_index;
    unsigned char output_buffer[ sha512_output_size ];
public:
    /// Create an mgf1 object seeded with the specific key
    /// @param[in] seed The seed value
    /// @param[in] seed_len The length of the seed in bytes
    mgf1_sha512( const unsigned char *seed, unsigned seed_len );

    /// Output the next sequence of bytes from the mgf1 object.
    /// Can be called multiple times to get successive outputs
    /// @param[out] buffer Where to place the bytes
    /// @param[in] len_output Number of bytes
    void output( unsigned char *buffer, unsigned len_ouptut );
};

} /* namespace sphincs_plus */

#endif /* SHA512_H_ */
