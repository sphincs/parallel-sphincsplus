#include "api.h"
#include "internal.h"

namespace sphincs_plus {

/* Length of a SHA512 hash */
const unsigned sha512_output_size = 64;

/* SHA512 processes blocks in 128 byte chunks */
const unsigned sha512_block_size = 128;

/* SHA512 context. */
typedef struct {
  unsigned long long state[8];       /* state; this is in the CPU native format */
  unsigned long long count;          /* number of bits processed so far */
  unsigned in_buffer;                /* number of bytes within the below */
                                     /* buffer */
  unsigned char buffer[128];         /* input buffer.  This is in byte vector format */
} SHA512_CTX;

void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const void *src, unsigned int count);
void SHA512Final(void *digest, SHA512_CTX *ctx);

class sha512 : public hash {
    SHA512_CTX ctx;
public:
    virtual void init(void) { SHA512_Init(&ctx); }
    virtual void update(const void *m, size_t len) { SHA512_Update( &ctx, m, len ); }
    virtual void final(void *m) { SHA512Final((unsigned char*)m, &ctx); }
    virtual size_t len_hash(void) { return sha512_output_size; }
    virtual size_t block_size(void) { return sha512_block_size; }
    virtual void zeroize(void) { sphincs_plus::zeroize( (void*)&ctx, sizeof ctx ); }
};

}  /* namespace sphincs_plus */
