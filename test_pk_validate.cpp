//
// This tests out the private key validation logic; this is optional logic
// that checks whether this private key is valid (and, say, is not actually
// intended for a different parameter set)
// This may sound like a fairly minor feature (possibly because it is),
// however testing it out also tests out other logic in general

#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include "api.h"
#include "test_sphincs.h"

using namespace sphincs_plus;

//
// We use the same 'randomness' for every key
static success_flag fixed_rng( void *target, size_t num_bytes ) {
    unsigned char* p = (unsigned char*)target;
    for (unsigned i=0; i<num_bytes; i++) {
	p[i] = i;
    }
    return success;
}

static bool do_test( key* keys[], bool fast_flag ) {
    const int max_priv_key = 128;
    unsigned char priv_keys[12][max_priv_key];

    // If we're in fast mode, only go through the F parameter sts
    // If we're in full mode, go through all parameter sets
    int z;
    if (fast_flag) z = 6; else z = 12;

    /* Generate the initial private keys */
    for (int i=0; i<z; i++) {
        if (!keys[i]->generate_key_pair( fixed_rng )) {
            printf( "*** KEY GENERATION FAILURE\n" );
	    return false;
	}
	int len_pk = keys[i]->len_private_key();
	if (len_pk > max_priv_key) {
            printf( "*** INTERNAL ERROR: PRIVATE KEY TOO LONG\n" );
	    return false;
	}
	const void *pk = keys[i]->get_private_key();
	if (!pk) {
            printf( "*** KEY GENERATION DID NOT GENERATE PRIVATE KEY\n" );
	    return false;
	}
	memcpy( priv_keys[i], pk, len_pk );
    }

    // Check all pair-wise key loads (both with validation on and off)
    for (int v=0; v<=1; v++) {
        bool val = (v == 1);
        for (int i=0; i<z; i++)
        for (int j=0; j<z; j++) {

	    key* k = keys[i];
	    k->set_validate_private_key(val);

	    success_flag claim = k->set_private_key( priv_keys[j] );

	    // Compute whether we expect that to have worked
	    success_flag expected = (!val || i==j) ? success : failure;

	    if (claim != expected) {
		printf( " UNEXPECTED: i=%d j=%d v=%d\n", i, j, v );
		return false;
	    }

	    // Also, if we loaded the wrong key (and we're not verifying)
	    // don't bother
	    if (i != j && !val) continue;

	    // Do we expect the signature operation to 'work'
	    bool expected_success = (i == j);
            try {
		const unsigned char message[] = "Hi there!";
                auto sig = k->sign(message, sizeof message);

		// It worked!  Did we expect it to?
	 	if (!expected_success) {
		    printf( " SIGNATURE WORKED WHEN WE EXPECT FAILURE: i=%d j=%d v=%d\n", i, j, v );
		    return false;
		}

		// Does the signature look valid?
                if (success != k->verify(sig.get(), k->len_signature(),
				         message, sizeof message)) {
		    printf( " SIGNATURE DID NOT VALIDATE: i=%d j=%d v=%d\n", i, j, v );
		    return false;
		}
	    } catch(std::exception& e) {
		// It didn't work - did we expect it to?
	 	if (expected_success) {
		    printf( " SIGNATURE FAILED WHEN WE EXPECT SUCCESS: i=%d j=%d v=%d\n", i, j, v );
		    return false;
		}
	    }
	}
    }

    return true;
}

#define RUN_TEST(n, fast) {                                \
    if (level == loud) {                                   \
	printf( " Checking L%d parameter sets\n", n/32 - 3 ); \
    }                                                      \
    key* keys[12];                                         \
    keys[ 0] = new key_sha256_   ## n ## f_simple;         \
    keys[ 1] = new key_sha256_   ## n ## f_robust;         \
    keys[ 2] = new key_shake256_ ## n ## f_simple;         \
    keys[ 3] = new key_shake256_ ## n ## f_robust;         \
    keys[ 4] = new key_haraka_   ## n ## f_simple;         \
    keys[ 5] = new key_haraka_   ## n ## f_robust;         \
    keys[ 6] = new key_sha256_   ## n ## s_simple;         \
    keys[ 7] = new key_sha256_   ## n ## s_robust;         \
    keys[ 8] = new key_shake256_ ## n ## s_simple;         \
    keys[ 9] = new key_shake256_ ## n ## s_robust;         \
    keys[10] = new key_haraka_   ## n ## s_simple;         \
    keys[11] = new key_haraka_   ## n ## s_robust;         \
                                                           \
    bool success = do_test(keys, fast);                    \
                                                           \
    for (int i=0; i<12; i++) delete keys[i];               \
                                                           \
    if (!success) return false;                            \
}

bool test_privkey_validate(bool fast_flag, enum noise_level level) {
    RUN_TEST(128, fast_flag);
    RUN_TEST(192, fast_flag);
    RUN_TEST(256, fast_flag);
    return true;
}
