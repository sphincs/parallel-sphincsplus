#include <string.h>
#include "internal.h"

namespace sphincs_plus {

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in)
{
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void u32_to_bytes(unsigned char *out, uint32_t in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen)
{
    unsigned long long retval = 0;
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8*(inlen - 1 - i));
    }
    return retval;
}

/*
 * This is a function to zeroize a section of memory
 *
 * We do this because when we release a section of memory (either because it's
 * a local variable going out of scope, or we free it), it's possible that
 * the memory will retain its contents after another allocation (possibly
 * done by someone outside this module).  So, to avoid this potential security
 * issue, we scrub the memory (at least, the parts that have data that would
 * make it possible to forge if it leaked) before releasing it.
 *
 * We use this, rather than having routines simply call memset, to avoid
 * potential problems with overenthusiastic optimizers.  Generally, we zeroize
 * an area immediately before it goes out of scope or we free it, however an
 * optimizer might conclude "they're about to release the memory, there's no
 * need to write to it first"
 */
void zeroize( void *area, size_t len ) {
#if defined( __STDC_LIB_EXT1__ )
    /*
     * C11 defines a version of memset that does precisely what we want, and
     * is guaranteed not to be molested by the optimizer
     * Note that the first 'len' is supposed to be the length of the buffer
     * we're cleaning and the second 'len' is the area to clear.  Since we
     * expect the caller to ask us to clear the entire area (and hence gives
     * us only one length), we use the same for both
     */
    memset_s( area, len, 0, len );
#else
    /*
     * Fallback code for pre-C11 versions
     */
    volatile unsigned char *p =
	            reinterpret_cast<volatile unsigned char*>(area);

    while (len--) *p++ = 0;
#endif
}

} /* namespace sphincs_plus */
