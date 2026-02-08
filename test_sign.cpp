#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out the signing process
// There isn't a great deal to check out (do we generate valid
// signatures?  Do the various APIs work as intended?), but we
// do what we can...


typedef bool (*random_function)( void *target, size_t num_bytes );

//
// This is an 'RNG' that always gives a fixed pattern
static bool fixed_rng( void *target, size_t num_bytes ) {
    unsigned char *p = (unsigned char *)target;
    while (num_bytes) {
        *p++ = num_bytes--;
    }
    return true;
}

//
// This is an 'RNG' that always a different pattern each time
// This uses CRC-16; not exactly cryptographicall secure
// especially since we advance the CRC only once for each
// byte output), but good enough for our purposes
static bool good_rng( void *target, size_t num_bytes ) {
    unsigned char *p = (unsigned char *)target;
    static uint32_t seed = 0x01;
    while (num_bytes--) {
        *p++ = seed & 0xff;
	uint32_t feedback = (1&(seed >> 15)) * 0x12F15;
	seed = (seed << 1) ^ feedback;
    }
    return true;
}

class sign_test {
    bool fast_flag;
    enum noise_level level;
public:
    sign_test( bool flg, enum noise_level lev ) {
        fast_flag = flg;
        level = lev;
    }
    bool run( slh_dsa::key& k, slh_dsa::key& v, const char *name, bool always );
};

//
// We have two different signature APIs; these give a copy
// interface to both
//  We also try it with the default opt_rand and having the caller
//  explicitly pass one in
static bool sign1( slh_dsa::key& k,
                   const unsigned char *msg, size_t len_msg,
                   unsigned char *sig_buffer) {
    return k.sign( sig_buffer, k.len_signature(),
                   msg, len_msg ) &&
	   k.verify( sig_buffer, k.len_signature(), msg, len_msg );
}
static bool sign1( slh_dsa::key& k,
                   const unsigned char *msg, size_t len_msg,
                   unsigned char *sig_buffer,
                   random_function rand ) {
    return k.sign( sig_buffer, k.len_signature(),
                   msg, len_msg, 0, 0, rand ) &&
	   k.verify( sig_buffer, k.len_signature(), msg, len_msg );
}
static bool sign2( slh_dsa::key& k,
                   const unsigned char *msg, size_t len_msg,
                   unsigned char *sig_buffer) {
    try {
        auto sig = k.sign_stl( msg, len_msg );
	memcpy( sig_buffer, sig.get(), k.len_signature() );
	return k.verify( sig_buffer, k.len_signature(), msg, len_msg );
    } catch(std::exception& e) {
        return false;
    }
}
static bool sign2( slh_dsa::key& k,
                   const unsigned char *msg, size_t len_msg,
                   unsigned char *sig_buffer,
                   random_function rand ) {
    try {
        auto sig = k.sign_stl( msg, len_msg, 0, 0, rand );
	memcpy( sig_buffer, sig.get(), k.len_signature() );
	return k.verify( sig_buffer, k.len_signature(), msg, len_msg );
    } catch(std::exception& e) {
        return false;
    }
}

bool sign_test::run( slh_dsa::key& k, slh_dsa::key& p,
                       const char* parameter_set_name, bool always ) {
        // If we're running in fast mode, skip any parameter set that is not
        // marked as always
    if (fast_flag && !always) return true;

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

    // Allocate the two signature buffers we'll use below
    unsigned len_sig = k.len_signature();
    std::unique_ptr<unsigned char[]>sig( new unsigned char[len_sig] );
    std::unique_ptr<unsigned char[]>sig2( new unsigned char[len_sig] );

    // Make sure that signing with an uninitialized key doesn't work
    static const unsigned char msg[1] = { 'x' }; /* Marks the spot */
    if (sign1( k, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH UNINITIALIZED KEY WORKED\n" );
        return false;
    }
    if (sign2( k, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH UNINITIALIZED KEY WORKED\n" );
        return false;
    }

    // Now initialize k with a private key
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION FAILURE\n" );
	return false;
    }

    // Make sure that signing with that private key works
    if (!sign1( k, msg, sizeof msg, sig.get())) {
        printf( "*** SIGNATURE GENERATION FAILURE 1a\n" );
	return false;
    }
    if (!sign2( k, msg, sizeof msg, sig.get())) {
        printf( "*** SIGNATURE GENERATION FAILURE 1b\n" );
	return false;
    }

    // Now try the same with a key initialized with a public key
    p.set_public_key( k.get_public_key() );
    if (sign1( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH PUBLIC KEY WORKED\n" );
        return false;
    }
    if (sign2( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH PUBLIC KEY WORKED\n" );
        return false;
    }

    // Now pass the private key to the other key, and make sure that
    // works
    p.set_private_key( k.get_private_key() );
    if (!sign1( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION FAILURE 2\n" );
        return false;
    }
    if (!sign2( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION FAILURE r3\n" );
        return false;
    }

    // Now we have checks on whether the signature is consistent when
    // it should be
    if (!sign1( k, msg, sizeof msg, sig.get(), 0 ) ||
        !sign2( p, msg, sizeof msg, sig2.get(), 0 )) {
        printf( "*** SIGNATURE GENERATION FAILURE 4\n" );
        return false;
    }
    if (0 != memcmp( sig.get(), sig2.get(), len_sig )) {
        printf( "*** DETERMANISTIC SIGNATURE GENERATION GAVE TWO DIFFERENT SIGNATURES\n" );
        return false;
    }

    if (!sign1( k, msg, sizeof msg, sig.get(), fixed_rng ) ||
        !sign2( p, msg, sizeof msg, sig2.get(), fixed_rng )) {
        printf( "*** SIGNATURE GENERATION FAILURE 5\n" );
        return false;
    }
    if (0 != memcmp( sig.get(), sig2.get(), len_sig )) {
        printf( "*** SIGNATURE GENERATION REPEATING RNG GAVE TWO DIFFERENT SIGNATURES\n" );
        return false;
    }

    // Now we have checks to see that the signature is different when it
    // should be
    if (!sign1( k, msg, sizeof msg, sig.get() ) ||
        !sign2( p, msg, sizeof msg, sig2.get() )) {
        printf( "*** SIGNATURE GENERATION FAILURE 6\n" );
        return false;
    }
    if (0 == memcmp( sig.get(), sig2.get(), len_sig )) {
        printf( "*** RANDOM SIGNATURE GENERATION GAVE THE SAME SIGNATURE\n" );
        return false;
    }

    if (!sign1( k, msg, sizeof msg, sig.get(), good_rng ) ||
        !sign2( p, msg, sizeof msg, sig2.get(), good_rng )) {
        printf( "*** SIGNATURE GENERATION FAILURE 7\n" );
        return false;
    }
    if (0 == memcmp( sig.get(), sig2.get(), len_sig )) {
        printf( "*** RANDOM SIGNATURE GENERATION GAVE THE SAME SIGNATURE\n" );
        return false;
    }

    // Check that we fail if the signature buffer isn't long enough
    if (k.sign( sig.get(), len_sig - 1, msg, sizeof msg )) {
        printf( "*** SIGNATURE GENERATION WITH TOO SMALL BUFFER WORKED\n" );
        return false;
    }

    // Now initialize p (that had the private key) with the public key,
    // make sure it lost the right to sign
    p.set_public_key( k.get_public_key() );
    if (sign1( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH PUBLIC KEY WORKED\n" );
        return false;
    }
    if (sign2( p, msg, sizeof msg, sig.get() )) {
        printf( "*** SIGNATURE GENERATION WITH PUBLIC KEY WORKED\n" );
        return false;
    }

    return true; 
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                                \
    CONCAT( slh_dsa::key_, PARM_SET) k, k2;                         \
    if (!s.run( k, k2, #PARM_SET, always )) {                       \
        return false;                                               \
    }                                                               \
}

bool test_sign(bool fast_flag, enum noise_level level) {
    sign_test s( fast_flag, level );

    // By default, we check all the 'F' parameter sets (they're fast)
    // and selected 'S' parameter sets
 
    // L1 parameter sets
    RUN_TEST( sha2_128s, false );
    RUN_TEST( sha2_128f, true );
    RUN_TEST( shake_128s, false ); 
    RUN_TEST( shake_128f, true );

    // L3 parameter sets
    RUN_TEST( sha2_192s, false );
    RUN_TEST( sha2_192f, true );
    RUN_TEST( shake_192s, false );
    RUN_TEST( shake_192f, true );

    // L5 parameter sets
    RUN_TEST( sha2_256s, false );
    RUN_TEST( sha2_256f, true );
    RUN_TEST( shake_256s, false );
    RUN_TEST( shake_256f, true );

    return true;
}
