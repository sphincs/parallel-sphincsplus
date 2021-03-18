//
// This is a shim betwen the NIST-like API to our API, should you insist on
// the NIST API
#include "../api.h"    // Our API
#include "./api.h"       // The NIST API
#include <string.h>
#include <exception>
extern "C" {
#include "rng.h"
}

//
// The NIST API assumes that the parameter set is compiled in
// This is what chooses it
#if !defined( SPX_PARAMETER_SET )
#define SPX_PARAMETER_SET sha256_128f_robust
#endif

#define CONCAT(a, b) CONCAT2(a, b)
#define CONCAT2(a, b) a ## b
typedef sphincs_plus :: CONCAT( key_, SPX_PARAMETER_SET ) KEY_TYPE;
    // sphincs_plus::key_sha256_128f_robust in the default case

extern "C" {    /* These functions use the C ABI */

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    KEY_TYPE k;
    return k.len_private_key();
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    KEY_TYPE k;
    return k.len_public_key();
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    KEY_TYPE k;
    return k.len_signature();
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    KEY_TYPE k;
    return k.len_randomness();
}

/*
 * Interface to NIST's prefered RNG
 */
static sphincs_plus::success_flag nist_random( void *target, size_t bytes ) {
    randombytes( (unsigned char*)target, bytes );
    return sphincs_plus::success;
}

/*
 * Kludge needed because our API wasn't designed to seed based on a
 * predetermined buffer
 */
static const unsigned char *seed_ptr;
static sphincs_plus::success_flag seed_random( void *target, size_t bytes ) {
    memcpy( target, seed_ptr, bytes );
    return sphincs_plus::success;
}

/*
 * Generates a key pair given a seed of length
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    KEY_TYPE k;
    seed_ptr = seed;

    sphincs_plus::success_flag f = k.generate_key_pair(seed_random);
    if (f != sphincs_plus::success) {
        return -1;
    }

    memcpy( sk, k.get_private_key(), k.len_private_key() );
    memcpy( pk, k.get_public_key(), k.len_public_key() );

    return 0;   // Success
}

/*
 * Generates a key pair.
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    KEY_TYPE k;

    //
    // We could just call k.generate_key_pair(), except that the NIST
    // known answer tests insist we call their RNG
    sphincs_plus::success_flag f = k.generate_key_pair( nist_random );
    if (f != sphincs_plus::success) {
        return -1;
    }

    memcpy( sk, k.get_private_key(), k.len_private_key() );
    memcpy( pk, k.get_public_key(), k.len_public_key() );

    return 0;   // Success
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    KEY_TYPE k;

    k.set_private_key(sk);

    *siglen = k.len_signature();

    // Here we would call k.set_num_thread(1) if we want to disable
    // threading
 
    sphincs_plus::success_flag f = k.sign(sig, *siglen, m, mlen, nist_random);

    if (f != sphincs_plus::success) {
        return -1;
    }
    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    KEY_TYPE k;
    k.set_public_key(pk);

    sphincs_plus::success_flag f = k.verify(sig, siglen, m, mlen);

    if (f != sphincs_plus::success) {
        return -1;
    }
    return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 *
 * The implementation in the reference code doesn't work if the output buffer
 * is the same as the input; I fixed this (mostly to show how the STL sign
 * interface works).  I could also move the message first, but what's the
 * fun in that???
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    KEY_TYPE k;
    k.set_private_key(sk);

    size_t siglen = k.len_signature();

    try {
        // Here we would call k.set_num_thread(1) if we want to disable
        // threading
        auto sig = k.sign(m, mlen, nist_random);

        memmove(sm + siglen, m, mlen);
        memcpy(sm, sig.get(), siglen);
        *smlen = mlen + siglen;

        return 0;
    } catch(std::exception& e) {
        return -1;   // Currently can't happen; in this code, we're
                     // being careful to handle error conditions,
                     // even impossible ones
    }
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    KEY_TYPE k;
    size_t sig_len = k.len_signature();

    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly sig_len bytes */
    if (smlen < sig_len) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - sig_len;

    k.set_public_key(pk);

    sphincs_plus::success_flag f = k.verify(sm, sig_len, sm+sig_len, *mlen);

    if (f != sphincs_plus::success) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + sig_len, *mlen);

    return 0;
}

}    /* extern "C" */
