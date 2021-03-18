#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out the various thread options

class thread_test {
    bool fast_flag;
    enum noise_level level;
public:
    thread_test( bool flg, enum noise_level lev ) {
        fast_flag = flg;
        level = lev;
    }
    bool run( sphincs_plus::key& k, const char *name, bool always );
};

// We need to generate the signatures in determanistic mode
static bool sign( sphincs_plus::key& k,
                  const unsigned char *msg, size_t len_msg,
                  unsigned char *sig_buffer) {
    return k.sign( sig_buffer, k.len_signature(),
                   msg, len_msg, 0 ) &&
	   k.verify( sig_buffer, k.len_signature(), msg, len_msg );
}

bool thread_test::run( sphincs_plus::key& k,
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

    // Now initialize k with a private key
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION FAILURE\n" );
	return false;
    }

    static const unsigned char msg[1] = { '@' }; /* Right here */

    // Generate the signature with one thread
    k.set_num_thread(1);
    if (!sign( k, msg, sizeof msg, sig.get())) {
        printf( "*** SIGNATURE GENERATION FAILURE\n" );
	return false;
    }

    // Iterate through the possible number of threads, and make
    // sure they generate the same signature
    for (int thread = 2; thread <= 16; thread++) {
        k.set_num_thread(thread);

	memset( sig2.get(), 0, len_sig );
        if (!sign( k, msg, sizeof msg, sig2.get())) {
            printf( "*** SIGNATURE GENERATION FAILURE\n" );
            return false;
        }

	if (0 != memcmp( sig.get(), sig2.get(), len_sig )) {
            printf( "*** SIGNATURE GENERATION INCONSISTENT\n" );
            return false;
        }
    }

    return true; 
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                            \
    CONCAT( sphincs_plus::key_, PARM_SET) k;                    \
    if (!s.run( k, #PARM_SET, always )) {                       \
        return false;                                           \
    }                                                           \
}

bool test_thread(bool fast_flag, enum noise_level level) {
    thread_test s( fast_flag, level );

    // By default, we check all the 'F' parameter sets (they're fast)
    // and selected 'S' parameter sets
 
    // L1 parameter sets
    RUN_TEST( sha256_128s_simple, true );
    RUN_TEST( sha256_128f_simple, true );
    RUN_TEST( sha256_128s_robust, false );
    RUN_TEST( sha256_128f_robust, true );
    RUN_TEST( shake256_128s_simple, false ); 
    RUN_TEST( shake256_128f_simple, true );
    RUN_TEST( shake256_128s_robust, false );
    RUN_TEST( shake256_128f_robust, true );
    RUN_TEST( haraka_128s_simple, false );
    RUN_TEST( haraka_128f_simple, true );
    RUN_TEST( haraka_128s_robust, true );
    RUN_TEST( haraka_128f_robust, true );

    // L3 parameter sets
    RUN_TEST( sha256_192s_simple, false );
    RUN_TEST( sha256_192f_simple, true );
    RUN_TEST( sha256_192s_robust, false );
    RUN_TEST( sha256_192f_robust, true );
    RUN_TEST( shake256_192s_simple, false );
    RUN_TEST( shake256_192f_simple, true );
    RUN_TEST( shake256_192s_robust, false );
    RUN_TEST( shake256_192f_robust, true );
    RUN_TEST( haraka_192s_simple, true );
    RUN_TEST( haraka_192f_simple, true );
    RUN_TEST( haraka_192s_robust, false );
    RUN_TEST( haraka_192f_robust, true );

    // L5 parameter sets
    RUN_TEST( sha256_256s_simple, false );
    RUN_TEST( sha256_256f_simple, true );
    RUN_TEST( sha256_256s_robust, false );
    RUN_TEST( sha256_256f_robust, true );
    RUN_TEST( shake256_256s_simple, false );
    RUN_TEST( shake256_256f_simple, true );
    RUN_TEST( shake256_256s_robust, false );
    RUN_TEST( shake256_256f_robust, true );
    RUN_TEST( haraka_256s_simple, true );
    RUN_TEST( haraka_256f_simple, true );
    RUN_TEST( haraka_256s_robust, false );
    RUN_TEST( haraka_256f_robust, true );

    return true;
}
