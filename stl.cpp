#include <memory>
#include <stdexcept>
#include "api.h"

//
// This defines the version of sign that avoids a potential mishap with memory
// (either accidental memory overwrite or memory leak)
// It returns a unique_ptr, which we allocate (and hence we know will be long
// enough), and has a built in destructor (which will free the array when the
// caller is done with it)

namespace slh_dsa {

std::unique_ptr<unsigned char[]> key::sign_stl(
        const unsigned char *message, size_t len_message,
	const void *context, size_t len_context,
        const random& rand) {
    size_t sig_len = len_signature();
    std::unique_ptr<unsigned char[]>signature( new unsigned char[sig_len] );

    sign_flag flag = sign_internal(signature.get(), sig_len,
            0x00,   // Not prehashed
	    context, len_context,
	    0, 0,   // No hash OID
            message, len_message, rand);

    switch (flag) {
    case sign_success:
	return signature;
    case sign_no_private_key:
        throw std::runtime_error( "no SLH-DSA private key" );
    case sign_bad_context_len:
        throw std::runtime_error( "bad context" );
    default:
        throw std::runtime_error( "unknown error" );
    }
}

// And the prehash version
std::unique_ptr<unsigned char[]> key::sign_stl(
        const unsigned char *message, size_t len_message,
	const hash_type& hash,
	const void *context, size_t len_context,
        const random& rand) {
    if (len_message != hash.length) {
	// We insist that the length of the hash be what we expect
        throw std::runtime_error( "bad hash length" );
    }

    size_t sig_len = len_signature();
    std::unique_ptr<unsigned char[]>signature( new unsigned char[sig_len] );

    sign_flag flag = sign_internal(signature.get(), sig_len,
            0x01,   // Prehashed
	    context, len_context,
	    hash.oid, hash.oid_length,   // The hash OID
            message, len_message, rand);

    switch (flag) {
    case sign_success:
	return signature;
    case sign_no_private_key:
        throw std::runtime_error( "no SLH-DSA private key" );
    case sign_bad_context_len:
        throw std::runtime_error( "bad context" );
    default:
        throw std::runtime_error( "unknown error" );
    }
}

}  /* namespace slh_dsa */
