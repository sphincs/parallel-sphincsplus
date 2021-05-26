#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <immintrin>
#include "api.h"

namespace sphincs_plus {

//
// Call rdrand to fill the buffer with randomness
//
// Subtle note: this will call _rdrand64_step one more time than necessary,
// and will completely ignore the last value returned.  It does that so that
// the final value on the stack when we return will be that last value (that
// we ignored), which is uncorrelated to anything we put into target
success_flag rdrand_fill( void* target, size_t bytes_to_fill) {
    unsigned char* buffer = (unsigned char*)target;
    unsigned long long temp;

    for (;;) {
	if (0 == _rdrand64_step( &temp )) {
            // rdrand failed
	    return failure;
	}

	if (bytes_to_fill == 0) break;

        size_t next_to_fill = bytes_to_fill;
	if (next_to_fill > 8) next_to_fill = 8;

	memcpy( buffer, &temp, next_to_fill );

	buffer += next_to_fill;
	bytes_to_fill -= next_to_fill;
    }

    return success;
}

} /* namespace sphincs_plus */
