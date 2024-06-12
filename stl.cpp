#include <memory>
#include <stdexcept>
#include "api.h"

//
// This defines the version of sign that avoids a potential mishap with memory
// (either accidental memory overwrite or memory leak)
// It returns a unique_ptr, which we allocate (and hence we know will be long
// enough), and has a built in destructor (which will free the array when the
// caller is done with it)

namespace sphincs_plus {

std::unique_ptr<unsigned char[]> key::sign(
        const unsigned char *message, size_t len_message,
        const random& rand) {
    size_t sig_len = len_signature();
    std::unique_ptr<unsigned char[]>signature( new unsigned char[sig_len] );

    success_flag worked = sign(signature.get(), sig_len,
                               message, len_message, rand);

    if (worked != success) {
        if (!have_private_key) {
            // We rather need a private key to sign
            throw std::runtime_error( "no Sphincs+ private key" );
        } else {
            // The only other possible failure reason
            throw std::runtime_error( "fault detected during Sphincs+ signature process" );
        }
    }

    return signature;
}

}  /* namespace sphincs_plus */
