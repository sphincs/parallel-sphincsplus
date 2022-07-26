#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out the key generation process
// There isn't a great deal to check out (do we generate valid
// public/private keypairs?  Do the various APIs work as intended?), but we
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
// This is an RNG that fails
static bool bad_rng( void *target, size_t num_bytes ) {
    (void)target;
    (void)num_bytes;
    return false;
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

class keygen_test {
    bool fast_flag;
    enum noise_level level;
public:
    keygen_test( bool flg, enum noise_level lev ) {
        fast_flag = flg;
        level = lev;
    }
    bool run( sphincs_plus::key& k, const char *name, bool always );
};

bool keygen_test::run( sphincs_plus::key& k,
                       const char* parameter_set_name, bool always ) {
        // If we're running in fast mode, skip any parameter set that is not
        // marked as always
    if (fast_flag && !always) return true;

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

    unsigned len_pub = k.len_public_key();
    unsigned len_priv = k.len_private_key();
    std::unique_ptr<unsigned char[]>pub_k( new unsigned char[len_pub] );
    unsigned char *pub_key = pub_k.get();
    std::unique_ptr<unsigned char[]>priv_k( new unsigned char[len_priv] );
    unsigned char *priv_key = priv_k.get();

        // Make sure that attempting to generate a key with no random
	// source doesn't work
    if (k.generate_key_pair(0)) {
        printf( "*** KEY GENERATION WITH NO ENTROPY WORKED\n" );
        return false;
    }

        // Make sure that attempting to generate a key with a random
	// source that fails doesn't work
    if (k.generate_key_pair(bad_rng)) {
        printf( "*** KEY GENERATION WITH NO ENTROPY WORKED\n" );
        return false;
    }

        // Make sure tht attempting to generate a key with the default
	// random source does work
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION WITH DEFAULT ENTROPY DIDN'T WORK\n" );
        return false;
    }

        // Same the public and private keys and try again
    memcpy( pub_key, k.get_public_key(), len_pub );
    memcpy( priv_key, k.get_private_key(), len_priv );
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION WITH DEFAULT ENTROPY DIDN'T WORK\n" );
        return false;
    }
        // Make sure that it generated different keys
    if (0 == memcmp( pub_key, k.get_public_key(), len_pub) ||
        0 == memcmp( priv_key, k.get_private_key(), len_priv)) {
        printf( "*** KEY GENERATION WITH DEFAULT ENTROPY REPEATED KEYS\n" );
        return false;
    }

        // Make sure tht attempting to generate a key with a good
	// random source does work
    if (!k.generate_key_pair(good_rng)) {
        printf( "*** KEY GENERATION WITH GOOD ENTROPY DIDN'T WORK\n" );
        return false;
    }

        // Same the public and private keys and try again
    memcpy( pub_key, k.get_public_key(), len_pub );
    memcpy( priv_key, k.get_private_key(), len_priv );
    if (!k.generate_key_pair(good_rng)) {
        printf( "*** KEY GENERATION WITH GOOD ENTROPY DIDN'T WORK\n" );
        return false;
    }
        // Make sure that it generated different keys
    if (0 == memcmp( pub_key, k.get_public_key(), len_pub) ||
        0 == memcmp( priv_key, k.get_private_key(), len_priv)) {
        printf( "*** KEY GENERATION WITH GOOD ENTROPY REPEATED KEYS\n" );
        return false;
    }

        // Make sure tht attempting to generate a key with a fixed
	// random source does work
    if (!k.generate_key_pair(fixed_rng)) {
        printf( "*** KEY GENERATION WITH FIXED ENTROPY DIDN'T WORK\n" );
        return false;
    }

        // Save the public and private keys and try again
    memcpy( pub_key, k.get_public_key(), len_pub );
    memcpy( priv_key, k.get_private_key(), len_priv );
    if (!k.generate_key_pair(fixed_rng)) {
        printf( "*** KEY GENERATION WITH FIXED ENTROPY DIDN'T WORK\n" );
        return false;
    }
        // Make sure that it generated the same keys
    if (0 != memcmp( pub_key, k.get_public_key(), len_pub) ||
        0 != memcmp( priv_key, k.get_private_key(), len_priv)) {
        printf( "*** KEY GENERATION WITH FIXED ENTROPY GENERATED DIFFERENT KEYS\n" );
        return false;
    }

    return true; 
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                                \
    CONCAT( sphincs_plus::key_, PARM_SET) k;                        \
    if (!s.run( k, #PARM_SET, always )) {                           \
        return false;                                               \
    }                                                               \
}

bool test_keygen(bool fast_flag, enum noise_level level) {
    keygen_test s( fast_flag, level );

    // By default, we check all the 'F' parameter sets (they're fast)
    // and selected 'S' parameter sets
 
    // L1 parameter sets
    RUN_TEST( sha2_128s_simple, true );
    RUN_TEST( sha2_128f_simple, true );
    RUN_TEST( sha2_128s_robust, false );
    RUN_TEST( sha2_128f_robust, true );
    RUN_TEST( shake_128s_simple, true ); 
    RUN_TEST( shake_128f_simple, true );
    RUN_TEST( shake_128s_robust, false );
    RUN_TEST( shake_128f_robust, true );
    RUN_TEST( haraka_128s_simple, false );
    RUN_TEST( haraka_128f_simple, true );
    RUN_TEST( haraka_128s_robust, true );
    RUN_TEST( haraka_128f_robust, true );

    // L3 parameter sets
    RUN_TEST( sha2_192s_simple, false );
    RUN_TEST( sha2_192f_simple, true );
    RUN_TEST( sha2_192s_robust, false );
    RUN_TEST( sha2_192f_robust, true );
    RUN_TEST( shake_192s_simple, false );
    RUN_TEST( shake_192f_simple, true );
    RUN_TEST( shake_192s_robust, false );
    RUN_TEST( shake_192f_robust, true );
    RUN_TEST( haraka_192s_simple, false );
    RUN_TEST( haraka_192f_simple, true );
    RUN_TEST( haraka_192s_robust, false );
    RUN_TEST( haraka_192f_robust, true );

    // L5 parameter sets
    RUN_TEST( sha2_256s_simple, false );
    RUN_TEST( sha2_256f_simple, true );
    RUN_TEST( sha2_256s_robust, false );
    RUN_TEST( sha2_256f_robust, true );
    RUN_TEST( shake_256s_simple, false );
    RUN_TEST( shake_256f_simple, true );
    RUN_TEST( shake_256s_robust, false );
    RUN_TEST( shake_256f_robust, true );
    RUN_TEST( haraka_256s_simple, false );
    RUN_TEST( haraka_256f_simple, true );
    RUN_TEST( haraka_256s_robust, false );
    RUN_TEST( haraka_256f_robust, true );

    return true;
}
