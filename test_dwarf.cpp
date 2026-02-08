#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

bool disable_on_fast(bool fast_flag) {
    if (fast_flag) {
        printf( "  Test skipped - test takes too long for fast mode\n" );
        return false;
    }
    return true;
}

//
// This tests out the limited-signature (dwarf) parameter sets

class dwarf_test {
    enum noise_level level;
public:
    dwarf_test( enum noise_level lev ) {
        level = lev;
    }
    bool run( slh_dsa::key& k, const char *name );
};

bool dwarf_test::run( slh_dsa::key& k, const char* parameter_set_name ) {

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

    // Allocate the a signature buffer we'll use below
    unsigned len_sig = k.len_signature();
    std::unique_ptr<unsigned char[]>sig( new unsigned char[len_sig] );

    // Now initialize k with a private key
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION FAILURE\n" );
	return false;
    }

    // Use the parameter set name as the message
    const unsigned char *msg = (const unsigned char *)parameter_set_name;
    size_t len_msg = strlen(parameter_set_name);

    // Make sure that signing works
    if (!k.sign( sig.get(), len_sig, msg, len_msg )) {
        printf( "*** SIGNATURE GENERATION FAILURE 1\n" );
        return false;
    }

    // Make sure that we can verify
    if (!k.verify( sig.get(), len_sig, msg, len_msg )) {
        printf( "*** SIGNATURE VERIFICATION FAILURE\n" );
        return false;
    }

    // And that's the test we're running
    return true;
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET) {                                \
    CONCAT( slh_dsa::key_, PARM_SET) k;                     \
    if (!s.run( k, #PARM_SET )) {                           \
        return false;                                       \
    }                                                       \
}

bool test_dwarf(bool, enum noise_level level) {
    dwarf_test s( level );

    // L1 parameter sets
    RUN_TEST( sha2_rls128cs1 );
    RUN_TEST( shake_rls128cs1 );

    // L3 parameter sets
    RUN_TEST( sha2_rls192cs1 );
    RUN_TEST( shake_rls192cs1 );

    // L5 parameter sets
    RUN_TEST( sha2_rls256cs1 );
    RUN_TEST( shake_rls256cs1 );

    return true;
}
