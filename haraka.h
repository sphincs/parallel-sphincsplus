#if !defined( HARAKA_H_ )
#define HARAKA_H_

#include "immintrin.h"

namespace sphincs_plus {

typedef uint64_t u64;
typedef __m128i u128;

class haraka512 {
    const u128* rc;
public:
    haraka512( const u128* this_seed ) : rc(this_seed) { ; }

    void permute( u128* data );
};

class harakaS {
    union {
        unsigned char buffer[64];
	u128 long_buffer[4];
    };
    unsigned index;
    haraka512 perm;
public:
    harakaS( const u128* seed ) : perm(seed) {
                      index = 0;
                      memset( buffer, 0, 64 );
    }
    void absorb( const unsigned char* msg, unsigned len_msg );
    void finalize( void );
    void squeeze( unsigned char* output, unsigned len_output );
};

class haraka512_4x {
    const u128* rc;
public:
    haraka512_4x( const u128* this_seed ) : rc(this_seed) { ; }

    void permute( u128*, u128*, u128*, u128*,
                  const u128 *, const u128 *, const u128 *, const u128 * );
    void transform( u128*, u128*, u128*, u128*,
                  const u128 *, const u128 *, const u128 *, const u128 * );
};

class harakaS_4x {
    union {
        unsigned char buffer[4][64];
	u128 u128_buffer[4][4];
    };
    haraka512_4x perm;
    unsigned index;
public:
    harakaS_4x( const u128* seed ) : perm(seed) {
        memset( buffer, 0, sizeof buffer ); index = 0;
    }
    void absorb( unsigned char** msg, unsigned len_msg );
    void finalize( void );
    void squeeze( unsigned char** output, unsigned len_output );
};

class haraka256_4x {
    const u128* rc;
public:
    haraka256_4x( const u128* this_seed ) : rc(this_seed) { ; }

    void transform( u128*, u128*, u128*, u128*,
                    const u128*, const u128*, const u128*, const u128* );
};

} /* namespace sphincs_plus */

#endif /* HARAKA_H_ */
