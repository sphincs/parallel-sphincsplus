#include <string.h>
#include <stdint.h>
#include "api.h"
#include "internal.h"

using namespace sphincs_plus;

// Register the Sphincs+ geometry
// We expect that this is called only during construction
void key::set_geometry( size_t len_hash, size_t k, size_t t,
                       size_t h, size_t d, size_t wots_digits ) {

    len_hash_ = len_hash;;
    k_ = k;
    t_ = t;
    h_ = h;
    d_ = d;
    wots_digits_ = wots_digits;
    merkle_height_ = h/d;
    wots_bytes_ = len_hash * wots_digits;
}

void key::set_public_key(const unsigned char *public_key) {
    memcpy( keys + PRIVKEY_PUBLICKEY_OFFSET * len_hash(), public_key,
            LEN_PUBKEY * len_hash() );
    have_private_key = false;
    have_public_key = true;
}

void key::set_private_key(const unsigned char *private_key) {
    memcpy( keys, private_key, LEN_PRIVKEY * len_hash() );
    have_private_key = true;
    have_public_key = true;
}

const unsigned char* key::get_public_key(void) {
    if (!have_public_key) return 0;
    return keys + PRIVKEY_PUBLICKEY_OFFSET * len_hash();
}

const unsigned char* key::get_private_key(void) {
    if (!have_private_key) return 0;
    return keys;
}

/* Get the length of a public key */
size_t key::len_public_key(void) {
    /* The public key consists of two hash-length values */
    return LEN_PUBKEY * len_hash();
}

/* Get the length of a private key */
size_t key::len_private_key(void) {
    /* The private key consists of four hash-length values */
    return LEN_PRIVKEY * len_hash();
}

/* Get the length of a signature */
size_t key::len_signature(void) {
    return len_hash() * (1 + k() * (t()+1) + h() + d() * wots_digits());
}

/* Generate a public/private keypair */
success_flag key::generate_key_pair(std::shared_ptr<random> rand) {
    size_t n = len_hash();
    unsigned char priv_key[ LEN_PRIVKEY * max_len_hash ];

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */

    switch (rand->randFunc( priv_key, 3*n )) {
    case random_success:
        break;
    default: return failure; // On anything other than unqualified success
    }


    /* Initialize our hash function with the private and public seeds */
    /* The root will be wrong - we'll fix that up later in this function */
    set_private_key(priv_key);

   /* Compute the root node of the top-most subtree */
    addr_t top_tree_addr = {0};
    addr_t wots_addr = {0};

    /* We're computing the top level Merkle tree */
    set_layer_addr(top_tree_addr, d() - 1);
    set_layer_addr(wots_addr, d() - 1);

    merkle_sign(NULL, priv_key + PRIVKEY_ROOT_OFFSET * n,
                wots_addr, top_tree_addr,
                ~0 /* ~0 means "don't bother generating an auth path */ );

    /* And set our internal copy of the private key (now with the correct */
    /* root value) */
    set_private_key(priv_key);

    zeroize(priv_key, LEN_PRIVKEY * n);

    return success;
}

// These functions don't have any error checking
const unsigned char* key::get_secret_seed(void) {
    return keys + PRIVKEY_SECRETSEED_OFFSET * len_hash();
}
const unsigned char* key::get_prf(void) {
    return keys + PRIVKEY_PRF_OFFSET * len_hash();
}
const unsigned char* key::get_public_seed(void) {
    return keys + PRIVKEY_PUBLICSEED_OFFSET * len_hash();
}
const unsigned char* key::get_root(void) {
    return keys + PRIVKEY_ROOT_OFFSET * len_hash();
}

// The default F function falls back to the thash
// This is used for SHA-256 and SHAKE-256 - Haraka uses a different definition
void key::f_xn(unsigned char **out, unsigned char **in, addr_t* addrxn) {
    thash_xn(out, in, 1, addrxn);
}

// The random generator we almost always use - ask the random number to
// give us randomness

key::key(void) {
    // We currently do not have either a public nor a private key pair
    have_public_key = false;
    have_private_key = false;

    // We initialize the offset parameters to what most hash functions use
    // SHA-256 will update these field values
    offset_layer = 3;
    offset_tree = 8;
    offset_type = 19;
    offset_kp_addr1 = 23;
    offset_kp_addr2 = 22;
    offset_chain_addr = 27;
    offset_hash_addr = 31;
    offset_tree_hgt = 27;
    offset_tree_index = 28;

    num_thread = default_thread;
}

key::~key(void) {
    zeroize( keys, sizeof keys );  // We don't have to zeroize everything,
                                   // however let's be thorough
}
/* namespace sphincs_plus */
