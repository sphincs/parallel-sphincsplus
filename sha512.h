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

    /// Initialize the context to be consistent with the prehashed state
    /// set in init.
    /// @param[in] init Prehashed state to set the SHA-512 state to
    /// @param[in] count Number of prehashed bytes in the prehashed state
    ///                  Must be a multiple of SHA-256 block size (64)
    void init_from_intermediate(const sha512_state init, unsigned int count);

    /// Add more data to the hash being computed
    /// @param[in] msg String to add to the hash
    /// @param[in] count Length of the string
    void update(const void *msg, size_t count);

    /// We're done adding data to the hash; now compute the final results
    /// @param[out] digest Where to place the hash
    void final(unsigned char *digest);

    /// Store the hash intermediate value (so we can continue the hash
    /// computation later).  Valid only if the data we've hashed is multiple
    /// of 128 bytes in length
    /// @param[out] intermediate Where to store the intermediate value
    void export_intermediate(sha512_state intermedate);

    /// Erase the hash state.  Used if we've hashed sensitive data and
    /// we need to free the hash object
    void zeroize(void) { sphincs_plus::zeroize( this, sizeof *this ); }

    static const unsigned hash_size = sha512_output_size;
};

} /* namespace sphincs_plus */

#endif /* SHA512_H_ */
