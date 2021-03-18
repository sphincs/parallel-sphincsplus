#if !defined( NIST_API_H_ )
#define NIST_API_H_

#include <stdint.h>
#include <stdlib.h>

#if defined( __cplusplus)
extern "C" {
#endif 

#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES ((int)crypto_sign_secretkeybytes())
#define CRYPTO_PUBLICKEYBYTES ((int)crypto_sign_publickeybytes())
#define CRYPTO_BYTES          ((int)crypto_sign_bytes())
#define CRYPTO_SEEDBYTES      ((int)crypto_sign_seedbytes())

unsigned long long crypto_sign_secretkeybytes(void);
unsigned long long crypto_sign_publickeybytes(void);
unsigned long long crypto_sign_bytes(void);
unsigned long long crypto_sign_seedbytes(void);
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#if defined( __cplusplus)
}
#endif

#endif /* NIST_API_H_ */
