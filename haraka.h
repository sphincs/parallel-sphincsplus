#if !defined( HARAKA_H_ )
#define HARAKA_H_

#include "immintrin.h"

/// \file haraka.h
/// \brief This contains the declaration of the low level Haraka classes

namespace sphincs_plus {

typedef uint64_t u64;
typedef __m128i u128;

/// This is a class that computes the Haraka512 permutation
class haraka512 {
    const u128* rc;
public:
    /// Create a haraka512 object based on a specific seed
    haraka512( const u128* this_seed ) : rc(this_seed) { ; }

    /// Permute the 64 byte object based on the seed
    /// @param data Data to permute
    void permute( u128* data );
};

/// This is a class that implementates the Haraka keyed XOF
class harakaS {
    /// This is the current state of the XOF permutation
    union {
        unsigned char buffer[64];
        u128 long_buffer[4];
    };
    unsigned index;   //<! The current byte index into the state
                      //<! capacity (the first 32 bytes of the buffer)
    haraka512 perm;   //<! The keyed permutation we use to transform the state
public:
    /// Initialize the XOF with the particular key
    harakaS( const u128* seed ) : perm(seed) {
                      index = 0;
                      memset( buffer, 0, 64 );
    }
    /// Absorb a string of bytes
    /// @param[in] msg  Bytes to absorb
    /// @param[in] len_msg  Number of bytes to absorb
    void absorb( const unsigned char* msg, unsigned len_msg );

    /// Inform the harakaS that we're done absorbing
    /// This step must be done before squeezing
    void finalize( void );

    /// Squeeze a number of bytes
    /// @param[out] output Where to place the squeezed bytes
    /// @param[in] len_output Number of bytes to squeeze
    void squeeze( unsigned char* output, unsigned len_output );
};

/// Class which performs four Haraka512 operations in parallel on
/// the same seed 
class haraka512_4x {
    const u128* rc;   //<! Our key
public:
    /// Initialize the haraka512_4x object with the seed
    /// @param[in] this_seed The seed to use
    haraka512_4x( const u128* this_seed ) : rc(this_seed) { ; }

    /// Permute four different 64 byte values
    void permute( u128* , u128* , u128* , u128* ,
                  const u128 *, const u128 *, const u128 *, const u128 * );

    /// Transform (noninvertabily) four different 64 byte values
    void transform( u128*, u128*, u128*, u128*,
                  const u128 *, const u128 *, const u128 *, const u128 * );
};

/// This is a class that implementates the Haraka keyed XOF on four different
/// inputs at the same time
class harakaS_4x {
    /// This is the current state of all four XOF permutations
    union {
        unsigned char buffer[4][64];
        u128 u128_buffer[4][4];
    };
    haraka512_4x perm; //<! The keyed permutation we use to transform the state
    unsigned index;   //<! The current byte index into the state
                      //<! capacity (the first 32 bytes of the buffer)
		      //<! Note that all four XOFs are kept in sync, hence
		      //<! we need only one index
public:
    /// Initialize the XOF with the particular key
    harakaS_4x( const u128* seed ) : perm(seed) {
        memset( buffer, 0, sizeof buffer ); index = 0;
    }

    /// Absorb four strings of bytes into all four XOFs
    /// @param[in] msg  Vector of four (unsigned char*) pointing to the
    ///                 bytes to absorb
    /// @param[in] len_msg  Number of bytes to absorb
    void absorb( unsigned char** msg, unsigned len_msg );

    /// Inform the harakaS_4x that we're done absorbing
    /// This step must be done before squeezing
    void finalize( void );

    /// Squeeze a number of bytes from all four XOFs
    /// @param[out] output Vector of four (unsigned char*) pointing to the
    ///                 where to squeeze to
    /// @param[in] len_output Number of bytes to squeeze
    void squeeze( unsigned char** output, unsigned len_output );
};

/// This is a class that computes the Haraka256 noninvertable transform on
/// four 32 byte strings
class haraka256_4x {
    const u128* rc;    //<! Our key
public:
    /// Initialize the object with the particular key
    haraka256_4x( const u128* this_seed ) : rc(this_seed) { ; }

    /// Transform (noninvertabily) four different 32 byte values
    void transform( u128*, u128*, u128*, u128*,
                    const u128*, const u128*, const u128*, const u128* );
};

} /* namespace sphincs_plus */

#endif /* HARAKA_H_ */
