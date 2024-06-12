//
// This tests out the fault detection logic of Sphincs+
//
// This works by injecting errors and seeing what happens

#include <cstdio>
#include <stdbool.h>
#include <string.h>
#include <exception>
#include "api.h"
#include "test_sphincs.h"

enum f_type { prf, f, thash_f, // The types of functions that we can inject
                               // a fault into; that is, cause to return an
                               // incorrect value
              f_type_count };

static enum f_type next_test( enum f_type f ) {
    return (enum f_type)(f + 1);
}

//
// This is a specialized key which can programmably miscompute
// This declares alternative virtual functions that can introduce
// errors; this way, we can introduce faults without changing the
// logic of the signer
//
// Deriving a subclass based on the key type and redefining its
// internal functions is evil (a necessary evil in this case, but
// still evil)
// Don't try this at home
//
// We run this test against a single parameter set; I don't expect
// fault detection to be parameter-set specific, so I just picked
// the fastest one
class faulty_key : public sphincs_plus::key_haraka_128f_simple {
    typedef sphincs_plus::key_haraka_128f_simple parent;
    bool do_error;   // If false, we're not injecting a fault
    enum f_type what_type;  // If we are injecting a fault, which function
                     // are we doing it to?
    uint32_t count[ f_type_count ];  // The number of times each function
                     // has been used since the last reset_count()
    uint32_t target_count; // If the function in queston has been used
                     // precisely target_count times, then inject the fault
protected:
    // These are the instrumented internal functions
    virtual void prf_addr_xn(unsigned char **out,
              const sphincs_plus::addr_t* addrxn);
    virtual void f_xn(unsigned char **out, unsigned char **in,
              sphincs_plus::addr_t* addr);
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, sphincs_plus::addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, sphincs_plus::addr_t* addrxn);
    // Note that we dont't try to tweak the h_msg and prf_msg
    // functions; those wouldn't cause an exploitable error
public:
    faulty_key(void) { do_error = false; }

    void reset_count(void) { memset( count, 0, sizeof count ); }
    uint32_t get_count(enum f_type type) { return count[ type ]; }
 
        // Set a fault to happen in the future
    void set_error(enum f_type type, uint32_t target) {
        do_error = true; what_type = type; target_count = target;
    }

        // On a fault, we don't care if the top level Merkle
        // signature was affected (as that can't be leveraged into
        // a forgery); hence we don't need to compare that part of
        // the signature.  That Merkle signature happens to be the last
        // part of the Sphincs+ signature, hence we just test the
        // earlier parts
    size_t len_critial_sig(void) {
        return len_signature() - merkle_height() * len_hash();
    }
};

void faulty_key::prf_addr_xn(unsigned char **out,
                             const sphincs_plus::addr_t* addrxn) {
    parent::prf_addr_xn(out, addrxn);
    if (do_error && what_type == prf && count[prf] == target_count) {
        // Inject an error
        out[0][0] ^= 0x01;
    }
    count[prf]++;
}

void faulty_key::f_xn(unsigned char **out, unsigned char **in,
                      sphincs_plus::addr_t* addr) {
    parent::f_xn(out, in, addr);
    if (do_error && what_type == f && count[f] == target_count) {
        // Inject an error
        out[0][0] ^= 0x01;
    }
    count[f]++;
}

void faulty_key::thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, sphincs_plus::addr_t addr) {
    parent::thash(out, in, inblocks, addr);
    if (do_error && what_type == thash_f && count[thash_f] == target_count) {
        // Inject an error
        out[0] ^= 0x01;
    }
    count[thash_f]++;
}

void faulty_key::thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, sphincs_plus::addr_t* addrxn) {
    parent::thash_xn(out, in, inblocks, addrxn);
    if (do_error && what_type == thash_f && count[thash_f] == target_count) {
        // Inject an error
        out[0][0] ^= 0x01;
    }
    count[thash_f]++;
}

bool test_fault(bool fast_flag, enum noise_level level) {
    faulty_key k;

    // Generate the key
    if (!k.generate_key_pair()) {
        printf( "*** KEY GENERATION FAILED\n" );
        return false;
    }

    const unsigned char msg[] = "Hello";
    const unsigned int msg_len = 5;

    // Generate the known good signature (turning off fault detection)
    k.set_fault_detection(false);
    auto sig = k.sign( msg, msg_len, 0 );
    unsigned sig_len = k.len_signature();

    // To be thorough, check if the signature validates
    if (!k.verify( sig.get(), sig_len, msg, msg_len )) {
        printf( "*** INITIAL SIGNATURE GENERATION DID NOT VALIDATE\n" );
        return false;
    }

    // Threading will confuse our faulting logic - turn it off
    k.set_num_thread(1);

    // Turn on the fault detection logic
    k.set_fault_detection(true);

    // Try to generate a signature (and while we're at it, count how
    // many times each function is called)
    k.reset_count();
    try {
        auto sig2 = k.sign( msg, msg_len, 0 );
        // We generated a signature; make sure it's the same
        if (0 != memcmp( sig.get(), sig2.get(), sig_len )) {
            printf( "*** TURNING ON FAULT DETECTION CHANGED THE SIGNATURE\n" );
            return false;
        }
    } catch(std::exception& e) {
        printf( "*** FAULT DETECTED WHEN ONE WAS NOT INJECTED\n" );
        return false;
    }

    // Now, we'll introduce faults, and see what happens

    // On the fast test, introduce errors only occasionally
    // On a full test, introduce errors at every possible location
    unsigned incr;
    if (fast_flag) incr = 43; else incr = 1;

    // First of all, characterize how many times each function is called
    // while we're generating the signature
    uint32_t count[f_type_count];
    uint32_t total_tests = 0;
    for (enum f_type test = prf; test < f_type_count; test = next_test(test)) {
        count[test] = k.get_count(test); 
        total_tests += (count[test] + incr - 1) / incr;
    }

    size_t len_crit = k.len_critial_sig();

    // Now, repeatedly generate signatures, while introducing faults at
    // systematically applied locations
    uint32_t count_test = 0;
    int last_percentage = -1;
    for (enum f_type test = prf; test < f_type_count; test = next_test(test)) {
        if (level == loud) {
            const char* testname;
            switch(test) {
            case prf: testname = "PRF"; break;
            case f: testname = "F"; break;
            case thash_f: testname = "THASH"; break;
            default: testname =  "???"; break;
            }
            printf( " Testing whether faults during %s are detected\n",
                    testname );
        }
        uint32_t attempts = 0;
        uint32_t error_caught = 0;
    
        for (uint32_t pos = 0; pos < count[test]; pos += incr) {
            if (level != quiet) {
                int this_percentage = 100.0 * count_test / total_tests;
               	if (this_percentage != last_percentage) {
                    printf( " %d%%\r", this_percentage );
                    fflush(stdout);
                    last_percentage = this_percentage;
                }
            }
            count_test++;
            attempts++;
            k.reset_count();
            k.set_error(test, pos);  // Cause the pos'th evaluation of the
                                     // function indicated by test to be wrong
            try {
                auto sig2 = k.sign( msg, msg_len, 0 );
                // We generated a signature withot the fault detection logic
                // triggering (which can happen if the function was used in
                // the top level Merkle tree, or we tweaked a track that
                // wasn't actually used); make sure the parts we care about
                // have not changed
                if (0 != memcmp( sig.get(), sig2.get(), len_crit )) {
                    printf( "*** UNDETECTED FAULT: test = %d pos = %u\n",
                           (int)test, (unsigned)pos );
                    return false;
                }
            } catch(std::exception& e) {
                // We detected the error
                error_caught++;
            }
        }
    
        if (2*error_caught < attempts) {
            printf( "*** SOMETHING'S WRONG WITH THE TEST: DETECTED FAULT %u out of %u trials\n", error_caught, attempts );
            return false;
        }
    }

    return true;    
}
