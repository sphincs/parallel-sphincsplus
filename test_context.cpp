#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out the context feature of SLH-DSA

class context_test {
    bool fast_flag;
    enum noise_level level;
public:
    context_test( bool flg, enum noise_level lev ) {
        fast_flag = flg;
        level = lev;
    }
    bool run( slh_dsa::key& k, const char *name, bool always );
};

bool context_test::run( slh_dsa::key& k,
                       const char* parameter_set_name, bool always ) {
        // If we're running in fast mode, skip any parameter set that is not
        // marked as always
    if (fast_flag && !always) return true;

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

        // Create a parameter set
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION FAILED\n" );
        return false;
    }

    bool hard_failure = false;
    const int num_contexts = 6;  // We current test 6 different contexts
                                 // The first one is the default
    struct context {
        unsigned len;
	char context[255];
    } contexts[num_contexts-1] = {
	{ 0, "" },    // Explicit NULL context
	{ 1, "A" },  // 1 character context
	{ 1, "B" },  // 1 character context
	{ 2, "AB" }, // 2 character context
	{ 2, "BA" }, // 2 character context
    };
    unsigned char *sigs[num_contexts];

    unsigned len_sig = k.len_signature();
    unsigned char message[] = "Hello spots fans";
    for (int i=0; i<num_contexts; i++) {
	sigs[i] = new unsigned char[len_sig];

	slh_dsa::success_flag s;
	if (i == 0) {
	    s = k.sign(sigs[i], len_sig, message, sizeof message );
	} else {
	    s = k.sign(sigs[i], len_sig, message, sizeof message,
	             contexts[i-1].context, contexts[i-1].len );
	}
	if (s != slh_dsa::success) {
	    printf( "*** Failure during signature generation\n" );
	    hard_failure = true;
	}
    }
    if (hard_failure) {
	goto free_all;
    }

    /* Step through them and verify all combinations */
    for (int i=0; i<num_contexts; i++) {
        for (int j=0; j<num_contexts; j++) {
	    slh_dsa::success_flag s, expected_s;

	    // We expect success if either we're testing the same context
	    // that we original used, or we're testing the (0,1) or (1,0) set
	    expected_s = (i == j) || ((i|j) == 0x01) ? slh_dsa::success : slh_dsa::failure;
	
	    if (i == 0) {
	        s = k.verify(sigs[j], len_sig, message, sizeof message );
	    } else {
	        s = k.verify(sigs[j], len_sig, message, sizeof message,
	             contexts[i-1].context, contexts[i-1].len );
	    }

	    if (s != expected_s) {
		hard_failure = true;
                if (s == slh_dsa::success) {
	            printf( "*** Verify succeeded %d %d (expected failure\n", i, j );
		} else {
	            printf( "*** Verify failed %d %d (expected success\n", i, j );
		}
		goto free_all;
           }
	}
    }

free_all:
    for (int i=0; i<num_contexts; i++) {
	delete[] sigs[i];
    }

    if (hard_failure) return false;

    // Possibly more tests

    return true; 
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                                \
    CONCAT( slh_dsa::key_, PARM_SET) k;                             \
    if (!s.run( k, #PARM_SET, always )) {                           \
        return false;                                               \
    }                                                               \
}

bool test_context(bool fast_flag, enum noise_level level) {
    context_test s( fast_flag, level );

    // By default, we check all the 'F' parameter sets (they're fast)
    // and none of the 'S' parameter sets (we expect that the context feature
    // to be independent of hypertree geometery
 
    // L1 parameter sets
    RUN_TEST( sha2_128f, true );
    RUN_TEST( sha2_128s, false );
    RUN_TEST( shake_128f, true ); 
    RUN_TEST( shake_128s, false );

    // L3 parameter sets
    RUN_TEST( sha2_192f, true );
    RUN_TEST( sha2_192s, false );
    RUN_TEST( shake_192f, true );
    RUN_TEST( shake_192s, false );

    // L5 parameter sets
    RUN_TEST( sha2_256f, true );
    RUN_TEST( sha2_256s, false );
    RUN_TEST( shake_256f, true );
    RUN_TEST( shake_256s, false );

    return true;
}
