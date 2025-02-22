#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out various test vectors published by NIST
//
// We are supposed to do the same transforms as what NIST requires
// that is, the same seed -> private/public key and the same
// private key/optrand/message -> signature operation
//
// This tries to verify that first one, by performing keygen with fixed inputs,
// and comparing the results against what the published NIST test vectors say
//

//
// Here is the set of test vectors extracted from the reference code
static struct w {
    const char *parameter_set_name; // Name of the parameter set
    unsigned seed_len;
    const char *seed;               // The seed
    unsigned public_key_len;
    const char *public_key;         // The expected public key
    unsigned private_key_len;
    const char *private_key;        // The expected private key
} vectors[] = {
#include "testvector_keygen.h"
};

//
class seed_buffer : public slh_dsa::random {
    const void *buffer;
    size_t len;
public:
    seed_buffer( const void *a, size_t b) : buffer(a), len(b) { ; }
    virtual enum slh_dsa::random_return operator()( void *target,
                                         size_t num_bytes ) const {
        if (num_bytes > len) return slh_dsa::random_failure;
        memcpy( target, buffer, num_bytes );
        return slh_dsa::random_success;
    }
};

// Given a parameter set name, return a key of that type
static slh_dsa::key* lookup_key( const char *name) {
    if (0 == strcmp( name, "SLH-DSA-SHA2-128f" ))
        return new slh_dsa::key_sha2_128f;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-128f" ))
        return new slh_dsa::key_shake_128f;
    if (0 == strcmp( name, "SLH-DSA-SHA2-128s" ))
        return new slh_dsa::key_sha2_128s;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-128s" ))
        return new slh_dsa::key_shake_128s;

    if (0 == strcmp( name, "SLH-DSA-SHA2-192f" ))
        return new slh_dsa::key_sha2_192f;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-192f" ))
        return new slh_dsa::key_shake_192f;
    if (0 == strcmp( name, "SLH-DSA-SHA2-192s" ))
        return new slh_dsa::key_sha2_192s;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-192s" ))
        return new slh_dsa::key_shake_192s;

    if (0 == strcmp( name, "SLH-DSA-SHA2-256f" ))
        return new slh_dsa::key_sha2_256f;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-256f" ))
        return new slh_dsa::key_shake_256f;
    if (0 == strcmp( name, "SLH-DSA-SHA2-256s" ))
        return new slh_dsa::key_sha2_256s;
    if (0 == strcmp( name, "SLH-DSA-SHAKE-256s" ))
        return new slh_dsa::key_shake_256s;

    printf( "*** UNRECOGNIZED PARAMETER SET %s\n", name );
    return 0;
}

//
// And here is the main code which actually runs the test
bool test_testvector_keygen(bool fast_flag, enum noise_level level) {

    const char *last_test = 0;

    for (unsigned i=0; i<sizeof vectors/sizeof *vectors; i++) {
        struct w& v = vectors[i];

	//
	// We really don't need the speed, but all those repeated parameter
	// sets looks odd on a -v, so we skip the repeats if we're not in
	// full mode
	if (fast_flag && last_test && 0 == strcmp( last_test, v.parameter_set_name )) {
	    continue;
	}
        last_test = v.parameter_set_name;

        if (level == loud) {
            printf( " Checking %s\n", v.parameter_set_name );
        }

        // Get the key
        slh_dsa::key* k = lookup_key( v.parameter_set_name );
        if (!k) return 0;

	// Load up the seed
	seed_buffer seed( reinterpret_cast<const unsigned char*>(v.seed),
			  v.seed_len );

	// And generate the public/private keypair
	slh_dsa::success_flag s = k->generate_key_pair(seed);
	if (s != slh_dsa::success) {
	    printf( "FAILURE IN KEY GENERATION\n" );
	    return false;
	}

	// Check if the public key is what we expect
	const unsigned char *key;
	key = k->get_public_key();
	if (!key || 0 != memcmp( key, v.public_key, v.public_key_len )) {
	    printf( "INCORRECT PUBLIC KEY\n" );
	}

	// Check if the private key is what we expect
	key = k->get_private_key();
	if (!key || 0 != memcmp( key, v.private_key, v.private_key_len )) {
	    printf( "INCORRECT PRIVATE KEY\n" );
	}

        // We're good for this parameter set
    }

    return 1;
}
