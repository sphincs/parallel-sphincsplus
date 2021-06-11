#include "api.h"
#include "internal.h"

/// \file wots.cpp
/// \brief Routines dealing with WOTS signatures

namespace sphincs_plus {

//
// This takes a message and derives the WOTS chain lengths
void key::chain_lengths(unsigned int *lengths,
                                  const unsigned char *msg) {
    // Convert the msg values into nybbles
    int i, j;
    int n = len_hash();
    int sum = 2*15*n;   // This will be the inverted sum
    for (i=j=0; i<n; i++) {
        unsigned char byte = msg[i];
        unsigned char digit = byte >> 4;
        lengths[j++] = digit;
        sum -= digit;
        digit = byte & 0xf;
        lengths[j++] = digit;
        sum -= digit;
    }

    // And append the inverted checksum (which is 3 bytes in all our
    // parameter sets)
    int d = (sum >> 8) & 0x0f;
    lengths[j++] = d;
    d = (sum >> 4) & 0x0f;
    lengths[j++] = d;
    d = (sum     ) & 0x0f;
    lengths[j  ] = d;
}

//
// This advances the wots hashes in the array the given number of WOTS
// positions as specified in the d_array
// This uses our fancy parallelized thash function, making this nontrivial
//
// This will trash the d_array structures (which is OK, rhe callers don't
// need it afterwards)
//
void key::compute_chains(unsigned char *array,
                             struct digit *d_array, addr_t* addrx) {
    int board[wots_w];   // This is the head of an array of linked lists of
                         // digits that need to be advanced.  A digit that
                         // needs to be advanced k more times will be in
                         // the list headed by board[k]
    int count[wots_w];   // The number of elements in each linked list
    int num_track = this->num_track(); // Number of digits we can advance at
                         //  once
    int digits = wots_digits();
    int n = len_hash();
    int i;
    const int eol = -1;  // -1 signifies 'end of list'

    for (i=0; i<wots_w; i++) {   // Initialize the board as empty
        board[i] = eol;
        count[i] = 0;
    }

    // Load all the digits onto the board
    for (i=0; i<digits; i++) {
        int c = d_array[i].count;
        d_array[i].pointer = board[c];
        board[c] = i;
        count[c] += 1;
    }

    int max_seen = wots_w;  // This will signify what level we have cleared
                            // off the board
    while (count[max_seen-1] == 0) max_seen--;

    for (;;) {
        // On each iteration of the loop, we take the top num_track digits
        // on the board and move them all down one step; we thash all the
        // digits that were moved
        if (max_seen == 1) break;   // Everything was moved to list 0
                                    // That means we're done

        // Scan for the top num_track elements
        int c = 0;      // Number of elements we've seen so far on this pass
        for (i = max_seen-1; i>0; i--) {
            if (c + count[i] >= num_track) {
                break;  // Rows i to max_seen-1 have enough elements
            }
            c += count[i];
        }
        if (i == 0) { i = 1; c = 0; }  // If we hit the bottom, use all
                                       // the elements not already on the
                                       // bottom

        // Load things up, starting with the first num_track-c elements
        // from row i
        int d = 0;
        int index[max_track];  // The elements we've seen
        for (; i < max_seen; i++) {
            int this_count = num_track - c;
            int p = board[i];
            int first_p = p;
            int last_p = -1;
            int moved = 0;
            // Scan the first this_count elements on list i
            // Note this there might not be this_count elements on the list
            for (int j=0; j < this_count && p >= 0; j++) {
                index[d++] = p;   // We scanned this digit; place it one our
                                  // list of digits to advance
                last_p = p;
                p = d_array[p].pointer;
                moved++;
            }
            if (last_p >= 0) {
                // Move the elements we scanned on list i from that list to
                // list i-1 to signify that we stepped those digits once
                board[i] = p;    // Remove them from list i
                d_array[last_p].pointer = board[i-1];  // Add them to
                board[i-1] = first_p;                  // list i-1
                count[i] -= moved;   // Adjust the size of each list
                count[i-1] += moved;
            }
            c = 0;
        }
        if (count[max_seen-1] == 0) max_seen--; // If we cleared out the
                 // the top list, make the one below that our new top list

        // And now that we've updated our accounting, go ahead and advance the
        // digits we've scanned
        unsigned char *vector[max_track];
        for (i=0; i<d; i++) {
            int digit = index[i];
            set_chain_addr( addrx[i], digit );
                // Set the position in the chain (and advance it for next
                // time)
            set_hash_addr( addrx[i], d_array[digit].index++ );
            vector[i] = array + n*digit;
        }
        unsigned char dummy_buffer[max_len_hash];
        for (; i<num_track; i++) {
            // If there are some unused tracks, point them to somewhere
            // harmless
            vector[i] = dummy_buffer;
        }

        // And step the digits forward 
        f_xn(vector, vector, addrx);
    }
}

} /* namespace sphincs_plus */
