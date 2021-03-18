#if !defined XN_INTERNAL_H_
#define XN_INTERNAL_H_

#include <stdint.h>
#include "internal.h"

namespace sphincs_plus {

/*
 * Structure used to pass information to wots_gen_leafx8
 */
struct leaf_info_xn {
    unsigned wots_sign_leaf;
    addr_t leaf_addr[max_track];
    addr_t pk_addr[max_track];
};

/*
 * Structure used to pass information to fors_gen_leafx8
 */
struct fors_gen_leaf_info_xn {
    unsigned revealed_idx;       // The index of the leaf to output
                                 // Includes idx_offset
    unsigned char *leaf_buffer;  // Where to write the leaf
    addr_t leaf_addrx[max_track];
};

} /* sphincs_plus */

#endif /* XN_INTENRAL_H_ */
