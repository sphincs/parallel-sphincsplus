#if !defined( MGF1_H_ )
#define MGF1_H_

namespace sphincs_plus {

/// This is the object that implements the MGF1 arbitrary-sized output function
/// It is parameterized by the hash function used (and the length of that hash
/// function; we need it because we hold a hash output, and we need to size the
/// buffer)
template <class hash_ctx, unsigned hash_len> class mgf1 {
    const unsigned char *message; //<! The string we're generating output from
    unsigned int message_len;  //<! The length of the string
    unsigned char state[4];   //<! The index of the output
    unsigned char output_index; //<! Where in the output_buffer we are
    unsigned char output_buffer[ hash_len ]; //<! The most recent hash
public:
    /// Create an mgf1 object seeded with the specific key
    /// @param[in] seed The seed value
    /// @param[in] seed_len The length of the seed in bytes
    mgf1(const unsigned char *seed, unsigned seed_len) {
	message = seed;
	message_len = seed_len;
        output_index = hash_len;
        state[0] = state[1] = state[2] = state[3] = 0;
    }

    /// Output the next sequence of bytes from the mgf1 object.
    /// Can be called multiple times to get successive outputs
    /// @param[out] buffer Where to place the bytes
    /// @param[in] len_output Number of bytes
    void output( unsigned char *buffer, unsigned len_output ) {
        for (;;) {
	    // See if we have some bytes left in the buffer
            unsigned left_in_buffer = hash_len - output_index;
            if (left_in_buffer > len_output) {
                left_in_buffer = len_output;
            }
            if (left_in_buffer > 0) {
		// We do; output those bytes
                memcpy( buffer, &output_buffer[output_index], left_in_buffer );
                output_index += left_in_buffer;
                buffer += left_in_buffer;
                len_output -= left_in_buffer;
            }
            if (len_output == 0) break;
    
            // Output buffer is empty; we need to generate some more
            hash_ctx ctx;
            ctx.init();
            ctx.update(message, message_len);
            ctx.update(state, 4);
            ctx.final(output_buffer);
            output_index = 0;
	    for (int i=3; i>=0; i--) {  // Increment the state for the next
		unsigned char c = (1 + state[i]) & 0xff; // output
		state[i] = c;
		if (c != 0) break;
	    }
	}
    }
};

} /* namespace sphincs_plus */

#endif /* MGF1_H_ */
