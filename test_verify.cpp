#include <cstdio>
#include <stdbool.h>
#include "api.h"
#include "test_sphincs.h"

class verify_test {
    bool fast_flag;
    enum noise_level level;
    uint32_t total_sig_len;
    uint32_t processed_sig_len;
    unsigned iter;
    int prev_percentage;
public:
    verify_test( bool flg, enum noise_level lev ) {
        fast_flag = flg;
        level = lev;
        total_sig_len = 0;
        processed_sig_len = 0;
        prev_percentage = -1;
    }
    void set_iter(unsigned it) { iter = it; }
    bool run( slh_dsa::key& k, slh_dsa::key& v, const char *name, bool always );
};

//
// The first key is what we use to generate the signature
// The second key is what we use to verify the signature; it is not given a copy
// of the private key
bool verify_test::run( slh_dsa::key& k, slh_dsa::key& v,
                       const char* parameter_set_name, bool always ) {
        // If we're running in fast mode, skip any parameter set that is not
        // marked as always
    if (fast_flag && !always) return true;

    size_t len_signature = k.len_signature();
    if (iter == 0) {
        // For the first iteration, we're just collecting signature lengths
	// (so that we can print the percentage completed)
        total_sig_len += len_signature;
        return true;
    }

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

    float current_percent = 0.0;
    float percentage_inc = 0.0;
    if (level >= whisper) {
        current_percent = 100 * (float)processed_sig_len / total_sig_len;
        percentage_inc = 100 * (float)1 / total_sig_len;
    }
    processed_sig_len += len_signature;

    // Create a random key pair
    if (!k.generate_key_pair()) {
        printf( "*** FAILURE GENERATING KEY\n" );
        return false;
    }

    // Pass the public key we just generated to the verification key
    const unsigned char *public_key = k.get_public_key();
    v.set_public_key(public_key);

    // Generate a signature for a simple message
    static const unsigned char message[3] = { 'a', 'b', 'c' };
    size_t len_message = sizeof message;
    auto sig = k.sign_stl( message, len_message );
    unsigned char *s = sig.get();

    // Make sure that it verifies
    if (!v.verify( s, len_signature, message, len_message )) {
        printf( "*** UNMODIFIED SIGNATURE DID NOT VALIDATE\n" );
        return false;
    }

    // Now step through the signature and flip bits; verify that those
    // flipped bits prevent the signature from validating
    unsigned increment = fast_flag ? 5 : 1;
    for (size_t offset = 0; offset < len_signature; offset += increment) {
        if (level >= whisper) {
            // Update the percentage completed if needed
            int this_percentage = (int)current_percent;
            if (this_percentage != prev_percentage) {
                printf( "%d%%\r", this_percentage );
                fflush(stdout);
                prev_percentage = this_percentage;
            }
            current_percent += increment * percentage_inc;
        }

        unsigned bit_increment = fast_flag ? 8 : 1;
        for (unsigned bit = 0; bit < 8; bit += bit_increment) {
            s[offset] ^= (1 << bit);

            // Make sure that it doesn't verify
            if (v.verify( s, len_signature, message, len_message )) {
                printf( "*** SIGNATURE VALIDATED FOR MODIFIED SIGNATURE\n" );
                return false;
            }

            s[offset] ^= (1 << bit);
        }
    }

    // Make sure that the message is back to how we found it
    if (!v.verify( s, len_signature, message, len_message )) {
        printf( "*** UNMODIFIED SIGNATURE DID NOT VALIDATE\n" );
        return false;
    }

    // Make sure that a too-short signature is rejected
    if (v.verify( s, len_signature, message, len_message-1 )) {
        printf( "*** SHORT SIGNATURE DID VALIDATE\n" );
        return false;
    }

    // Make sure that an incorrect message does not validate
    static const unsigned char wrong_message[3] = { 'd', 'e', 'f' };
    size_t len_wrong_message = sizeof wrong_message;
    if (v.verify( s, len_signature, wrong_message, len_wrong_message )) {
        printf( "*** INCORRECT MESSAGE DID VALIDATE\n" );
        return false;
    }

    return true;
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                                \
    CONCAT( slh_dsa::key_, PARM_SET) k, k2;                    \
    if (!v.run( k, k2, #PARM_SET, always )) {                       \
        return false;                                               \
    }                                                               \
}

bool test_verify(bool fast_flag, enum noise_level level) {
    verify_test v( fast_flag, level );

    for (unsigned iter=0; iter <= 1; iter++) {
        v.set_iter( iter );

        /*
         * Iterate through all the defined parameter sets
         * The ones marked 'true' we always do; we do the 'false'
         * ones only in '-full' mode
         */

        // L1 parameter sets
        RUN_TEST( sha2_128s, true );
        RUN_TEST( sha2_128f, false );
        RUN_TEST( shake_128s, true ); 
        RUN_TEST( shake_128f, false );

        // L3 parameter sets
        RUN_TEST( sha2_192s, true );
        RUN_TEST( sha2_192f, false );
        RUN_TEST( shake_192s, false );
        RUN_TEST( shake_192f, false );

        // L5 parameter sets
        RUN_TEST( sha2_256s, true );
        RUN_TEST( sha2_256f, false );
        RUN_TEST( shake_256s, false );
        RUN_TEST( shake_256f, false );
    }

    return true; 
}
