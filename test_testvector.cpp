#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include "api.h"
#include "test_sphincs.h"

//
// This tests out various test vectors from the reference code
//
// We are supposed to do the same transforms as the refence code;
// that is, the same seed -> private/public key and the same
// private key/optrand/message -> signature operation
//
// This tries to verify that both actually hold, by performing those
// operations with fixed inputs, and comparing them against what the
// reference code did with those same inputs (in the case of signatures, we
// hash the signatures, and compare hashes - there's no reason to include a
// 40k signature in our test files)
//
// For the public/private key generation, we use a fixed seed of
// the form 00 01 02 03 ...
//
// For signing, we use the optrand value specified in with the test
// vector
//
// Obvious question: why did we use an obviously nonrandom pattern
// for key generation, but a random one for signatures?  The answer
// is what the reference code allowed to do (without changing that
// code); the refernce code gave us an API (crypto_sign_seed_keypair)
// that allowed us to specify the seed, so we picked a simple one.
// In constrast, the reference code always called randombytes() to
// get optrand (and didn't give us an option to skip it); however
// the infrastructure did allow us to switch to a determanistic
// version of randombytes(), so that's what we did - that version
// gave us a random-looking pattern, so that's what we got

//
// Here is the set of test vectors extracted from the reference code
static struct v {
    const char *parameter_set_name; // Name of the parameter set
    unsigned char public_key[64];   // The public key that is generated with
                                    // the fixed seed
    unsigned char optrand[32];      // The optrand that was used when
                                    // creating the signature
    unsigned char hash_sig[32];     // The SHA256 hash of the signature of
                                    // of the message "abc", using the given
                                    // given optrand and generated private key
} vectors[] = {
#include "testvector.h"
};

// Given a parameter set name, return a key of that type
static sphincs_plus::key* lookup_key( const char *name) {
    if (0 == strcmp( name, "sha256_128f_simple" ))
        return new sphincs_plus::key_sha256_128f_simple;
    if (0 == strcmp( name, "sha256_128f_robust" ))
        return new sphincs_plus::key_sha256_128f_robust;
    if (0 == strcmp( name, "shake256_128f_simple" ))
        return new sphincs_plus::key_shake256_128f_simple;
    if (0 == strcmp( name, "shake256_128f_robust" ))
        return new sphincs_plus::key_shake256_128f_robust;
    if (0 == strcmp( name, "haraka_128f_simple" ))
        return new sphincs_plus::key_haraka_128f_simple;
    if (0 == strcmp( name, "haraka_128f_robust" ))
        return new sphincs_plus::key_haraka_128f_robust;
    if (0 == strcmp( name, "sha256_128s_simple" ))
        return new sphincs_plus::key_sha256_128s_simple;
    if (0 == strcmp( name, "sha256_128s_robust" ))
        return new sphincs_plus::key_sha256_128s_robust;
    if (0 == strcmp( name, "shake256_128s_simple" ))
        return new sphincs_plus::key_shake256_128s_simple;
    if (0 == strcmp( name, "shake256_128s_robust" ))
        return new sphincs_plus::key_shake256_128s_robust;
    if (0 == strcmp( name, "haraka_128s_simple" ))
        return new sphincs_plus::key_haraka_128s_simple;
    if (0 == strcmp( name, "haraka_128s_robust" ))
        return new sphincs_plus::key_haraka_128s_robust;

    if (0 == strcmp( name, "sha256_192f_simple" ))
        return new sphincs_plus::key_sha256_192f_simple;
    if (0 == strcmp( name, "sha256_192f_robust" ))
        return new sphincs_plus::key_sha256_192f_robust;
    if (0 == strcmp( name, "shake256_192f_simple" ))
        return new sphincs_plus::key_shake256_192f_simple;
    if (0 == strcmp( name, "shake256_192f_robust" ))
        return new sphincs_plus::key_shake256_192f_robust;
    if (0 == strcmp( name, "haraka_192f_simple" ))
        return new sphincs_plus::key_haraka_192f_simple;
    if (0 == strcmp( name, "haraka_192f_robust" ))
        return new sphincs_plus::key_haraka_192f_robust;
    if (0 == strcmp( name, "sha256_192s_simple" ))
        return new sphincs_plus::key_sha256_192s_simple;
    if (0 == strcmp( name, "sha256_192s_robust" ))
        return new sphincs_plus::key_sha256_192s_robust;
    if (0 == strcmp( name, "shake256_192s_simple" ))
        return new sphincs_plus::key_shake256_192s_simple;
    if (0 == strcmp( name, "shake256_192s_robust" ))
        return new sphincs_plus::key_shake256_192s_robust;
    if (0 == strcmp( name, "haraka_192s_simple" ))
        return new sphincs_plus::key_haraka_192s_simple;
    if (0 == strcmp( name, "haraka_192s_robust" ))
        return new sphincs_plus::key_haraka_192s_robust;

    if (0 == strcmp( name, "sha256_256f_simple" ))
        return new sphincs_plus::key_sha256_256f_simple;
    if (0 == strcmp( name, "sha256_256f_robust" ))
        return new sphincs_plus::key_sha256_256f_robust;
    if (0 == strcmp( name, "shake256_256f_simple" ))
        return new sphincs_plus::key_shake256_256f_simple;
    if (0 == strcmp( name, "shake256_256f_robust" ))
        return new sphincs_plus::key_shake256_256f_robust;
    if (0 == strcmp( name, "haraka_256f_simple" ))
        return new sphincs_plus::key_haraka_256f_simple;
    if (0 == strcmp( name, "haraka_256f_robust" ))
        return new sphincs_plus::key_haraka_256f_robust;
    if (0 == strcmp( name, "sha256_256s_simple" ))
        return new sphincs_plus::key_sha256_256s_simple;
    if (0 == strcmp( name, "sha256_256s_robust" ))
        return new sphincs_plus::key_sha256_256s_robust;
    if (0 == strcmp( name, "shake256_256s_simple" ))
        return new sphincs_plus::key_shake256_256s_simple;
    if (0 == strcmp( name, "shake256_256s_robust" ))
        return new sphincs_plus::key_shake256_256s_robust;
    if (0 == strcmp( name, "haraka_256s_simple" ))
        return new sphincs_plus::key_haraka_256s_simple;
    if (0 == strcmp( name, "haraka_256s_robust" ))
        return new sphincs_plus::key_haraka_256s_robust;

    printf( "*** UNRECOGNIZED PARAMETER SET %s\n", name );
    return 0;
}

//
// This is an 'RNG' that gives the fixed pattern that our
// test vectors expect on keygen
static bool fixed_rand( void *target, size_t num_bytes ) {
    unsigned char *p = (unsigned char *)target;
    for (unsigned i=0; i<num_bytes; i++) {
        *p++ = i;
    }
    return true;
}

//
// This is an 'RNG' that gives the optrand pattern that the signature
// generation expects
static unsigned char optrand_buffer[32];
static bool optrand_rng( void *target, size_t num_bytes ) {
    memcpy( target, optrand_buffer, num_bytes );
    return true;
}

// For our SHA256 implementation, we borrow the one from Sphincs
#include "sha256.h"
static void sha256( unsigned char *output,
                    const unsigned char *input, size_t len ) {
    sphincs_plus::SHA256_CTX ctx;
    ctx.init();
    ctx.update(input, len);
    ctx.final(output);
}

//
// And here is the main code which actually runs the test
bool test_testvector(bool fast_flag, enum noise_level level) {
    (void)fast_flag;  // Test is so fast there's no point in skipping some
                      // parameter sets

    for (unsigned i=0; i<sizeof vectors/sizeof *vectors; i++) {
        struct v& v = vectors[i];

        if (level == loud) {
            printf( " Checking %s\n", v.parameter_set_name);
        }

        // Get the key
        sphincs_plus::key* k = lookup_key( v.parameter_set_name );
        if (!k) return 0;

        // Generate the public/private key pair
        if (!k->generate_key_pair(fixed_rand)) {
            delete k;
            printf( "*** ERROR GENERATING KEY\n" );
            return 0;
        }

        // Check if it got the public key we expect
        if (0 != memcmp( v.public_key, k->get_public_key(),
                         k->len_public_key() )) {
            delete k;
            printf( "*** GENERATING DIFFERENT PUBLIC KEY FOR %s\n",
                    v.parameter_set_name );
            return 0;
        }

        // That passed; now on to the signature
        // Copy the optrand somewhere the optrand_rng can get it
        memcpy( optrand_buffer, v.optrand, 32 );

        static unsigned char message[3] = { 'a', 'b', 'c' };
        unsigned char* sig = new unsigned char[k->len_signature()];

        // And sign the message
        if (!k->sign( sig, k->len_signature(), message, sizeof message,
                      optrand_rng )) {
            delete[] sig;
            delete k;
            printf( "*** ERROR GENERATING SIGNATURE\n" );
            return 0;
        }

        // Hash the signature
        unsigned char hash[32];
        sha256( hash, sig, k->len_signature() );

        delete[] sig;   // We're done with these
        delete k;

        // Check if we got the expeccted hash
        if (0 != memcmp( v.hash_sig, hash, 32 )) {
            delete k;
            printf( "*** GENERATING DIFFERENT SGNATURES FOR %s\n",
                    v.parameter_set_name );
            return 0;
        }

        // We're good for this parameter set
    }

    return 1;
}
