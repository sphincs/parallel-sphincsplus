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
// This tries to verify the second, by performing those operations with fixed
// inputs, and comparing them against what the NIST test vectors had.
// For signatures, we hash them and compare hashes - there's no reason to
// include a
// 40k signature in our test files)
//

//
// Here is the set of test vectors extracted from the reference code
static struct v {
    const char *parameter_set_name; // Name of the parameter set
    const char *optrand;            // Optrand - NULL for determinstic
    const char *priv_key;           // The private key
    unsigned context_len;           // The length of the context
    const char *context;            // The context
    slh_dsa::hash_type *prehash;    // The prehash to use
                                    // NULL for pure
    unsigned message_len;           // The message length
    const char *message;            // The message (or the hash message if
                                    // we're testing prehash)
    unsigned char hash_sig[32];     // The SHA256 hash of the signature
} vectors[] = {
#include "testvector_sign.h"
};

//
// This class is here because the compiler insists on a virtual destructor
class our_random : public slh_dsa::random {
public:
    virtual ~our_random(void)  { ; }
};

class optrand_buffer : public our_random {
    const void *buffer;
    size_t len;
public:
    optrand_buffer( const void *a, size_t b) : buffer(a), len(b) { ; }
    virtual enum slh_dsa::random_return operator()( void *target,
                                         size_t num_bytes ) const {
        if (num_bytes > len) return slh_dsa::random_failure;
        memcpy( target, buffer, num_bytes );
        return slh_dsa::random_success;
    }
};

class optrand_default : public our_random {
public:
    virtual enum slh_dsa::random_return operator()( void *target,
                                         size_t num_bytes ) const {
	(void)target;     /* STUPID COMPILER */
	(void)num_bytes;
	return slh_dsa::random_default;
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

// For our SHA256 implementation, we borrow the one from Sphincs
#include "sha256.h"
static void sha256( unsigned char *output,
                    const unsigned char *input, size_t len ) {
    slh_dsa::SHA256_CTX ctx;
    ctx.init();
    ctx.update(input, len);
    ctx.final(output);
}


//
// And here is the main code which actually runs the test
bool test_testvector_sign(bool fast_flag, enum noise_level level) {
    bool did_prehash = false;
    bool did_deterministic = false;

    for (unsigned i=0; i<sizeof vectors/sizeof *vectors; i++) {
        struct v& v = vectors[i];

	if (fast_flag && did_prehash && v.prehash) continue;
	if (fast_flag && did_deterministic && !v.optrand) continue;

        if (level == loud) {
            printf( " Checking %s (%s)\n", v.parameter_set_name,
			    v.prehash ? "prehashed" : "pure" );
        }

        // Get the key
        slh_dsa::key* k = lookup_key( v.parameter_set_name );
        if (!k) return 0;

	// Load the private key
	k->set_private_key( reinterpret_cast<const unsigned char*>(v.priv_key) );

        // Generate the signature
	our_random *optrand = 0;
        if (v.optrand) {
	    optrand = new optrand_buffer( v.optrand, 32 );
	} else {
	    optrand = new optrand_default;
	    did_deterministic = true; // Don't forget
	}

        const unsigned char *message = reinterpret_cast<const unsigned char*>(v.message);
        unsigned char* sig = new unsigned char[k->len_signature()];

        // And sign the message
	slh_dsa::success_flag s;
	const unsigned char *context = reinterpret_cast<const unsigned char*>(v.context);
	if (v.prehash) {
	    // Prehash API
	    s = k->sign( sig, k->len_signature(), message, v.message_len,
                         *v.prehash, context, v.context_len, *optrand );

	    did_prehash = true; // Don't forget
	} else {
	    // Pure API
	    s = k->sign( sig, k->len_signature(), message, v.message_len,
                         context, v.context_len, *optrand );
	}
        if (s != slh_dsa::success) {
            delete[] sig;
            delete k;
	    delete optrand;
            printf( "*** ERROR GENERATING SIGNATURE\n" );
            return 0;
        }

        // Hash the signature
        unsigned char hash[32];
        sha256( hash, sig, k->len_signature() );

        delete[] sig;   // We're done with these
        delete k;
	delete optrand;

        // Check if we got the expeccted hash
        if (0 != memcmp( v.hash_sig, hash, 32 )) {
            printf( "*** GENERATING DIFFERENT SGNATURES FOR %s\n",
                    v.parameter_set_name );
            return 0;
        }

        // We're good for this parameter set
    }

    return 1;
}
