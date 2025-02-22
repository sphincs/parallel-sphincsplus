///
/// \file prehash.cpp
/// \brief This is the module that supports the prehash version of SLH-DSA
///
/// It's in a separate module because it is rarely used
///
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "internal.h"

namespace slh_dsa {

//
// The various prehash OIDs
//
// SHA256
hash_type ph_sha256 = {
    32, 11,
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
};

// SHA512
hash_type ph_sha512 = {
    64, 11,
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
};

// SHAKE-128 (32 byte output)
hash_type ph_shake128 = {
    32, 11,
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B"
};

// SHAKE-256 (64 byte otuput)
hash_type ph_shake256 = {
    64, 11,
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C"
};

//
// The prehash version of the sign routine
success_flag key::sign(
            unsigned char *signature, size_t len_signature_buffer,
            const unsigned char *message, size_t len_message,
	    const hash_type& hash,
	    const void *context, size_t len_context,
            const random& rand) {

    // Check if the message length is what we expect
    if (len_message != hash.length) {
        return failure;
    }

    // Do the actual signature
    sign_flag s = sign_internal(
            signature, len_signature_buffer,
	    0x01,           // Domain separator == "Prehashed"
	    context, len_context,
	    hash.oid, hash.oid_length,  // Include the oid
            message, len_message, rand);

    if (s == sign_success) {
	return success;
    } else {
	return failure;    // We don't bother reporting the failure reason
    }
}

// The C++ version of prehashed sign is in stl.cpp

//
// The prehashed version of verify
success_flag key::verify(
            const unsigned char *signature, size_t len_signature,
            const void *message, size_t len_message,
	    const hash_type& hash,
	    const void *context, size_t len_context) {

    // Note: we don't check if the message length is the expected hash
    // length.  Should we?
 
    return verify_internal( signature, len_signature,
	    0x01,           // Domain separator == "Prehashed"
	    context, len_context,
	    hash.oid, hash.oid_length,  // Include the oid
            message, len_message );
}

}  /* namespace slh_dsa */
