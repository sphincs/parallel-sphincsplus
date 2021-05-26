#include <iostream>
#include <cstdio>
#include "api.h"

static bool my_rand( void *target, size_t len ) {
    unsigned char *p = static_cast<unsigned char *>(target);
    size_t i;
    for (i=0; i<len; i++) {
        p[i] = i;
    }
    return true;
}

int main(void) {
    class sphincs_plus::key_sha256_192s_simple foo;
//    class sphincs_plus::key_sha256_192f_simple foo;
//    foo.set_num_thread(1);

    size_t len_pub_key = foo.len_public_key();
    std::cout << "Public key length = " << len_pub_key << "\n";

    size_t len_priv_key = foo.len_private_key();
    std::cout << "Private key length = " << len_priv_key << "\n";

    size_t len_signature = foo.len_signature();
    std::cout << "Signature length = " << len_signature << "\n";

    bool success = foo.generate_key_pair(my_rand);

    printf( "success = %d\n", success );
    if (!success) return 0;

    const unsigned char* pub_key = foo.get_public_key();
    size_t i;
    if (pub_key) {
        printf( "Public key:" );
        for (i=0; i<len_pub_key; i++) printf( "%c%02x", (i%16 == 0) ? '\n' : ' ', pub_key[i] );
        printf( "\n" );
    }

    const unsigned char* priv_key = foo.get_private_key();
    if (priv_key) {
        printf( "Private key:" );
        for (i=0; i<len_priv_key; i++) printf( "%c%02x", (i%16 == 0) ? '\n' : ' ', priv_key[i] );
        printf( "\n" );
    }

    unsigned char message[3] = { 'F', 'o', 'o' };
    unsigned char *sig = new unsigned char [len_signature];
 for (int i=0; i<1; i++) {
    success = foo.sign( sig, len_signature, message, sizeof message, 0 );
//    std::unique_ptr<unsigned char[]> sig = foo.sign(message, sizeof message, 0);
}
    printf( "signature success = %d\n", success );
    printf( "Signature:\n" );
    for (i=0; i<len_signature; i++) { if (i%16 == 0) printf( "%s%04x:", (i==0) ? "" : "\n", static_cast<int>(i) ); printf( " %02x", sig[i] ); }
    printf( "\n" );

#if 0
    success = foo.verify( sig.get(), len_signature, message, sizeof message );
#else
    success = foo.verify( sig, len_signature, message, sizeof message );
#endif
    printf( "verify success = %d\n", success );

//    delete[] sig;

    return 0;
}
