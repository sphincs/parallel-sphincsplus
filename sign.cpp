///
/// \file sign.cpp
/// \brief This is the module that actually generates a Sphincs+ signature
///
///
/// This is the module that actually generates a Sphincs+ signature
/// It uses multithreading to speed the signature generation process (which is
/// the main reason for this package)
///
/// Here is the general design: we split up the signature generation process
/// into 'tasks', where each task can be run independently, and place those
/// tasks into a queue.  We then spawn off a series of threads, and have each
/// one perform the next one on the queue (with the threads pulling tasks off
/// the queue in a 'first-come-first-serve' manner).  When all the tasks are
/// done and the queue is empty, we have fully generated the signature
///
/// Deviations from this overall logic:
/// - There's some computations that must be run first (e.g. hashing the
///   message) before we can start any such threading.  If the message being
///   signed is long, this nonparalleizable time may be considerable
/// - Some tasks need intermediate results from other tasks (and hence must
///   wait for those previous tasks).  We deal with this by having the previous
///   tasks schedule the next ones (when the intermediate results are
///   available)
///
/// Of course, when you have multiple threads working on the same task, you
/// must have rules about 'who can touch what memory'.  Here are the rules
/// we use:
/// - Memory is effectively divided into three sections; thread specific
///   memory, output buffers, and the common area
/// - Thread specific memory (which consists of thread-automatic data and
///   the task class members itself) is free for the thread to use at will
/// - Output buffers are the signature being generated, and the fors_root
///   and merkle_root array of the work_center.  Before writing into one
///   of these structures, the thread must lock() first (and then unlock()
///   afterwards.
///   - Note that the fors_root and merkle_root arrays are used as data
///     input to later tasks; however those later takes will run only after
///     the task that generated that output has completed the update and
///     unlock()'ed
///   - Common area - essentially, everything else.  This is treated as
///     read only by everyone (and so no lock()s are required).
/// The enqueue/next_task logic also references common data, but also does
/// a lock/unlock when doing so - those data members are not referenced by
/// tasks (and the work_center object itself has this logic)
///
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "api.h"
#include "internal.h"

namespace sphincs_plus {

class task;
/// This is the object that coordinates all the tasks being done for a
/// single signature operation
class work_center {
    task* head_q[2];        //<! For these pointers, the thread must be
    task* tail_q[2];        //<! locked before reading/writing these (if
                            //<! we're threading)
    unsigned mask;          //<! 1 -> place tasks in different queues based
	                    //<!      on if this is an even level or odd
	                    //<! 0 -> place all tasks in the same queue
	                    //<! This is here so that, if we're in fault
	                    //<! detection mode, we tend to use different
	                    //<! threads to do the double-checking
	
    uint64_t fors_done[2];  //<! Bitmask of which fors trees we have completed
    uint64_t fors_target;   //<! What the bitmask will look like when we've
                            //<! done them all
    friend class task;
    friend class worker;
    unsigned num_thread;    //<! Target number of threads (including the
                            //<! original thread)
    pthread_mutex_t write_lock; //<! If threads are active, this must be locked
                             //<! if the thread is writing to an output buffer
public:
    key* p;                 //<! The key we're signing with
    unsigned char* sig;     //<! Where to write the signature
    bool detected_fault;    //<! Did we detect a fault during the signature
                            //<! process
    uint32_t validated_wots; //<! Which WOTS signatures have we verified
    uint32_t wrote_wots;    //<! Which WOTS signatures have we written
  
    /// Create a work_center object
    /// @param[in] parm The key we are signing with
    /// @param[out] sig_buffer Where the signature will go
    work_center(key* parm, unsigned char* sig_buffer, unsigned m) {
        p = parm; sig = sig_buffer;
        head_q[0] = head_q[1] = tail_q[0] = tail_q[1] = 0;
        fors_done[0] = fors_done[1] = 0;
        fors_target = ((uint64_t)1 << parm->k()) - 1;
            // Get the number of threads
        num_thread = parm->num_thread;
        if (num_thread > max_thread) num_thread = max_thread;
            // Create the write mutex (if we need it; we don't in single
            // threaded mode)
        if (num_thread > 1) {
            if (0 != pthread_mutex_init( &write_lock, 0 )) {
                num_thread = 1;  // Can't create lock; fall back to 
                                 // single thread mode
            }
        }
        detected_fault = false;
        validated_wots = 0;
        wrote_wots = 0;
        mask = m;
    }

    /// Close up shop
    ~work_center() {
        if (num_thread > 1) {
            pthread_mutex_destroy( &write_lock );
        }
    }

    /// Must be called when a thread is about to write to a common area
    /// This is a mutex shared between threads - the time taken between
    /// lock() and unlock() must be small
    void lock(void) {
        if (num_thread > 1)
            pthread_mutex_lock( &write_lock );
    }
    /// Must be called when a thread is done writing to a common area
    void unlock(void) {
         if (num_thread > 1)
             pthread_mutex_unlock( &write_lock );
    }
    /// Where the various parts of the signature are, as well as which
    /// FORS/Merkle trees we'll be usig
    struct signature_geometry geo;

        /// This will hold the root values for the various FORS trees
    unsigned char fors_root[2][max_fors_trees*max_len_hash];

        /// This will hold the values to be signed by the Merkle trees
    unsigned char merkle_root[2][max_merkle_tree][max_len_hash];

        /// This will hold the values to be signed by each half of the Merkle
        /// tree
    unsigned char half_merkle_root[max_merkle_tree][2*max_len_hash];
    unsigned half_merkle_done[max_merkle_tree]; //<! Flags indicating whether
                  //<! each half of the Merkle tree has completed

    void enqueue( task *t );  //<! Put the task on the honey-do list
    task *next_task( void );  //<! Get the next task from the list
};

///
/// This is the object that performs a specific task.
/// Note that, sometimes, we'll reuse this object for another task
/// (if we perform another task immediately after finishing the
/// previous one)
class task {
        /// What task we have been assigned
    void (task::*func)(work_center *);
        /// Which FORS/Merkle tree we are working on
	/// Note: if we're signing a Merkle half-tree, we encode which half
	/// in the lsbit, and shift the actual level up one
    unsigned level;
    friend class work_center;
public:
    class task *next;
        /// Record which task to run in this structure
	/// Used both when the task is first initialized, and when this
	/// task is done, and it needs to spawn off another task
    void set_task(void (task::*func_p)(work_center *), unsigned lev ) {
       func = func_p;
       level = lev;
    }
        /// Perform the assigned task
    void do_it(work_center *w) { (this->*func)(w); }

        // The various tasks we might be assigned
        /// Build a FORS tree and authentication path
    void build_fors_tree(work_center *w);
        /// Hash all the FORS roots together
    void hash_fors(work_center *w);
        /// Generate a WOTS signature
    void build_wots_sig(work_center *w);
        /// Build a Merkle tree and authentication path
    void build_merkle_tree(work_center *w);
        /// Build half a Merkle tree and authentication path (and combine
	/// it with the other half if the othe half completes first)
    void build_half_merkle_tree(work_center *w);
};

class worker {
    work_center *center;
    unsigned index;
public:
    void assign_worker( work_center *wc, unsigned idx ) {
        center = wc;
        index = idx;
    }
    void do_job(void);
};

// Keep on doing things on the honey-do list until we run out
// If we are in fault-detection mode, then this task will go after one
// of the two queues, and stick with it until that queue is empty,
// and only then switching to the other queue
// We put the primary trees in one queue, and secondary in the other
// This maximizes the chance that two different threads will perform
// the redundant jobs (because they'll be on different queues)
// We set half our threads to start on queue 0, and the other half
// on queue 1, hence (assuming there's an even number of threads)
// we have some balance.
void worker::do_job(void) {
    for (;;) {
        // Get the next task off the work center list starting with the queue
        // we're currently on
        unsigned starting_index = index & center->mask;
        unsigned this_index = starting_index;
        task *t;
        center->lock();
        for (;;) {
            t = center->head_q[this_index];
            if (t) {
                center->head_q[this_index] = t->next;
                if (!center->head_q[this_index]) {
                    center->tail_q[this_index] = 0;
                }
                break;
            }
            // The current queue is empty; this about stepping to the next one
            index += 1;
            this_index = (this_index+1) & center->mask;
            if (this_index == starting_index) {
                // We cycled all the way around; nothing on any of the queues
                center->unlock();
                return;
            }
        }
        center->unlock();

        t->do_it(center);

    	  // Note: we don't have to worry about memory leaks; all
	      // the task structures come from the same automatic array
	      // and so will all be freed when we're done
    }
}

/// This is what a child thread runs - it just does the jobs it
/// can grab off the list
void *worker_thread( void *arg ) {
    worker* w = static_cast<worker*>(arg);
    w->do_job();
    return 0;
}

// Append this task onto the queue
void work_center::enqueue(task *t) {
    t->next = 0;

        // Appending this on either the even queue or the odd queue, based
        // on the lsbit of the level (assuming that we actually do use
        // two queues)
    unsigned index = t->level & mask;
    lock();

    if (tail_q[index]) { tail_q[index]->next = t; }
    tail_q[index] = t;
    if (!head_q[index]) { head_q[index] = t; }

    unlock();
}

///
/// This shifts right by 'shift' bits, doing the right thing
/// on a shift of 64
/// Needed because some parameter sets really do try to shift
/// the tree index by 64 at the top Merkle tree
static inline uint64_t shr(uint64_t a, unsigned shift ) {
    if (shift >= 64)
        return 0;
    else
        return a >> shift;
}

//
// The function that generates a signature
success_flag key::sign(
            unsigned char* signature, size_t len_signature_buffer,
            const unsigned char* message, size_t len_message,
            const random& rand) {
    // Make sure this key has the private key loaded
    if (!have_private_key) return false;

    size_t n = len_hash();
    unsigned i;
    int mask;
    if (detect_fault) {
        mask = 1;  // Put the primary tasks in one queue, the secondary
                   // tasks in another
    } else {
        mask = 0;  // Put all tasks in the same queue
    }
    work_center center(this, signature, mask);

    // Step 1: lay out where the various components of the signature are
    struct signature_geometry& geo = center.geo;

    size_t signature_length = initialize_geometry(geo);

    // Now, check if the buffer we were given is long enough
    if (signature_length > len_signature_buffer) {
        return failure;   // Buffer overflow - just say no
    }

    // Step 2 - generate the randomness
    unsigned char opt[ max_len_hash ];
    switch (rand( opt, n )) {
    case random_success:
        break;
    case random_failure: default:
        // Randomness failure detected; if we want to do something other
	// than default, we'd do it here
    case random_default:
        memcpy( opt, get_public_seed(), n );  // No optrand provided;
                                              // use the default
    }
    prf_msg( &signature[ geo.randomness_offset ],
             opt, message, len_message );

    // Step 3 - hash the message
    hash_message( geo, &signature[ geo.randomness_offset ],
                  message, len_message );

    // Step 4-: now it's time to schedule the various tasks that will
    // need to be done to generate the signature.  First, compute how
    // Merkle trees we'll want to be generated by a single task, and
    // how many Merkle trees we'll want to split between two tasks
    unsigned half_tree_start;
    if (num_thread == 1 || num_log_track() >= merkle_height()) {
        // Don't generate any half-trees, either because there's no
        // point with one thread, or because the trees are so shallow that
        // we can't
        half_tree_start = d();
    } else if (detect_fault) {
        // If we're in fault detection mode, our half-tree logic can't
        // handle that; however we don't use fault detection on the top
        // merkle tree, so we can do that in half-tree mode
        half_tree_start = d() - 1;
    } else {
        // We can do half-trees as we see fit
        // Here's the logic; start off with having all tracks do full
        // trees, until there's not enough trees left to support them
        // all - then, switch to half-trees
        // We also always do 2 half-trees, to absorb it if some tree
        // happened to take longer than others
        int target_half_tree_start = d() - 1;
        target_half_tree_start -= target_half_tree_start % num_thread;
        half_tree_start = target_half_tree_start;
    }

    // If we're not in fault-detection mode, build only the primary
    // tasks
    int incr;
    if (detect_fault) {
        incr = 1;  // In fault detection mode, build both the primary
                   // and secondary trees
    } else {
        incr = 2;  // In normal mode, just build the primary trees
    }

    // Step 4: put togther the list of the tasks needed to generate the
    // signature.  Note that some tasks will spawn others, so this isn't
    // the complete list
    // We are place the larger tasks first - this makes it more likely
    // that the tasks complete at about the same time
    task task_list[ 2*max_fors_trees + 2*max_merkle_tree ];
    int num_task = 0;
    for (i = 0; i < 2*half_tree_start; i += incr) {
        // Schedule the task to build Merkle tree (and write the
        // authentication path to the signature)
        if (i == 2*d() - 1) continue; // We don't need to build a
                                      // secondary of the top tree
        task_list[num_task].set_task( &task::build_merkle_tree, i );
        center.enqueue( &task_list[num_task] );
        num_task++;
    }
    // Schedule the task to build the result of the Merkle tree in
    // halves
    for (; i < 2*d(); i++) {
        task_list[num_task].set_task( &task::build_half_merkle_tree, i );
        center.enqueue( &task_list[num_task] );
        num_task++;
    }
    // And note that we haven't built any half-trees yet
    memset( center.half_merkle_done, 0, sizeof center.half_merkle_done );

    // And schedule the tasks to build the FORS trees 
    for (i = 0; i < 2*k(); i += incr) {
        task_list[num_task].set_task( &task::build_fors_tree, i );
        center.enqueue( &task_list[num_task] );
        num_task++;
    }

    worker w[max_thread];
    for (unsigned i=0; i<num_thread; i++) {
        w[i].assign_worker( &center, i );
    }
    // Now, spawn num_thread-1 child threads that will all do tasks
    // on the queue
    unsigned count_thread;
    pthread_t thread_id[max_thread];
    for (count_thread=1; count_thread < num_thread; count_thread++) {
        if (0 != pthread_create( &thread_id[count_thread], NULL,
                                 worker_thread, &w[count_thread] )) {
            // Couldn't create this child thread - go with what we have
            break;
        }
    }

    // And have the main thread do its part as well
    w[0].do_job();

    // The main thread is done -- wait for all the child threads to complete
    for (unsigned i=1; i < count_thread; i++) {
        void *status;
        pthread_join( thread_id[i], &status );
    }

    if (detect_fault) {
        // If we detected a fault, give up
        // We claim failure if someone triggered something, or
        // not all of the WOTS signatures were double-checked
        if (center.detected_fault || center.validated_wots != (1U << d()) - 1) {
            // Oops; the fault detection logic triggered
            memset( signature, 0, len_signature_buffer );
            return failure;
        }
    }

    // All the works been done - declare victory
    return success;
}

//
// This is the threaded procedure to generate one Merkle authentication path
// Note that this does not generate the WOTS signature - we can't, as we
// don't know the hash we'll be signing yet - that'll have to be a later task
void task::build_merkle_tree(work_center *w) {
    // The level encodes both the Merkle tree level, and if we're the
    // primary or the secondary
    unsigned actual_level = level / 2;
    unsigned half = level & 1;

    key& p = *w->p;
    unsigned n = p.len_hash();
    unsigned merkle_h = p.merkle_height();
    unsigned char auth_path[ max_len_hash * max_merkle_tree_height ];
    unsigned char root[ max_len_hash ];
    addr_t wots_addr = { 0 };
    addr_t tree_addr = { 0 };

    p.set_type(wots_addr, ADDR_TYPE_WOTS);
    p.set_type(tree_addr, ADDR_TYPE_HASHTREE);

    p.set_layer_addr(tree_addr, actual_level);
    p.set_tree_addr(tree_addr, shr( w->geo.idx_tree, merkle_h * actual_level));
    p.copy_subtree_addr(wots_addr, tree_addr);

    // Look up with leaf of the Merkle tree to generate the authentication
    // path for
    unsigned idx_leaf;
    if (half > 0) {
        // We're the secondary; no reason to ask merkle_sign for the
        // authentication path
        idx_leaf = ~0;
    } else if (actual_level == 0) {
        // Bottom tree - use the index generated from the message hash
        idx_leaf = w->geo.idx_leaf;
    } else {
        // Upper tree - extract the address from the tree index
        idx_leaf = (w->geo.idx_tree >> (merkle_h * (actual_level-1))) &
                    ((1 << merkle_h) - 1);
    }

    // Now call the function that'll do the real work
    p.merkle_sign( auth_path, root, wots_addr, tree_addr, idx_leaf );

    // Copy the authentication path to the signature
    // And, copy the root we computed to the work center (someone else
    // will need it)
    w->lock();
    if (half == 0) {
        memcpy( w->sig + w->geo.merkle[actual_level], auth_path, n * merkle_h );
    }
    if (actual_level != p.d()-1) {
        memcpy( w->merkle_root[half][actual_level+1], root, n );
    }
    w->unlock();

    // And if we're not the root, schedule the task that will do the
    // WOTS signature right above us
    // Since we're done with this task structure, just reuse it
    if (actual_level < p.d()-1) {
        set_task( &task::build_wots_sig, level+2 );
        w->enqueue(this);
    }
}

//
// This is the threaded procedure to generate a half of a Merkle tree
// Another task will be building the other half
//
// We do this to break up the size of each task, so that they can be
// load-balanced between threads better
void task::build_half_merkle_tree(work_center *w) {
    // The level encodes both the Merkle tree level, and which half we are
    // assigned
    unsigned actual_level = level / 2;
    unsigned half = level & 1;

    key& p = *w->p;
    unsigned n = p.len_hash();
    unsigned merkle_h = p.merkle_height();
    unsigned char auth_path[ max_len_hash * (max_merkle_tree_height-1) ];
    unsigned char root[ max_len_hash ];
    addr_t wots_addr = { 0 };
    addr_t tree_addr = { 0 };

    p.set_type(wots_addr, ADDR_TYPE_WOTS);
    p.set_type(tree_addr, ADDR_TYPE_HASHTREE);

    p.set_layer_addr(tree_addr, actual_level);
    p.set_tree_addr(tree_addr, shr(w->geo.idx_tree,  merkle_h * actual_level));
    p.copy_subtree_addr(wots_addr, tree_addr);

    // Look up with leaf of the Merkle tree to generate the authentication
    // path for
    unsigned idx_leaf;
    if (actual_level == 0) {
        // Bottom tree - use the index generated from the message hash
        idx_leaf = w->geo.idx_leaf;
    } else {
        // Upper tree - extract the address from the tree index
        idx_leaf = (w->geo.idx_tree >> (merkle_h * (actual_level-1))) &
                    ((1 << merkle_h) - 1);
    }

    // Check if the leaf is in our half
    bool in_our_half = (idx_leaf >> (merkle_h-1)) == half;
    if (!in_our_half) idx_leaf = ~0;
    else {
        // And the leaf id we'll pass to merkle_sign is relative to
        // our half
        idx_leaf &= (1 << (merkle_h-1)) - 1;
    }

    // Now call the function that'll do the real work
    p.merkle_sign( auth_path, root, wots_addr, tree_addr, idx_leaf,
                   1 + 2 * half );

    unsigned len_auth_string = n * (merkle_h - 1); // The length of
        // the authentication string we write, less the topmost entry

    // Copy the authentication path to the signature
    // And, copy the root we computed to the work center (someone else
    // will need it)
    w->lock();
        // Copy out the authentication path (if it lies in our half)
        // Copy out the top auth path entry (which is our root if the
        // leaf is in the other half)
    if (in_our_half) {
        memcpy( w->sig + w->geo.merkle[actual_level],
                auth_path, len_auth_string );
    } else {
        memcpy( w->sig + w->geo.merkle[actual_level] + len_auth_string,
                root, n  );
    }

        // Copy out the root we computed
    memcpy( &w->half_merkle_root[actual_level][half * n], root, n );
        // Mark our half as done
    unsigned done = w->half_merkle_done[actual_level] | (half+1);
    w->half_merkle_done[actual_level] = done;
    w->unlock();

    if (done != 0x03) {
        // Still waiting on the other half
        return;
    }

    if (actual_level == p.d() - 1) {
        // We don't actually need to compute the root for the top node
        return;
    }

    // Now compute the root
    p.set_tree_height(tree_addr, merkle_h);
    p.set_tree_index(tree_addr, 0);
    p.thash(root, w->half_merkle_root[actual_level], 2, tree_addr);

    // And publish the computed value
    w->lock();
    memcpy( w->merkle_root[0][actual_level+1], root, n );
    w->unlock();

    // And schedule the task that will do the WOTS signature right above us
    set_task( &task::build_wots_sig, 2*(actual_level + 1) );
    w->enqueue(this);
}

//
// This is the threaded procedure to generate one FORS authentication path
void task::build_fors_tree(work_center *w) {
    // The level encodes both the FORS tree index, and if we're the
    // primary or the secondary
    unsigned index = level / 2;
    unsigned half = level & 1;

    key& p = *w->p;
    unsigned n = p.len_hash();
    unsigned fors_h = p.t();
    addr_t wots_addr = { 0 };
    unsigned char signature[ max_len_hash * (max_merkle_tree_height+1) ];
    unsigned char root[ max_len_hash ];

    p.set_type(wots_addr, ADDR_TYPE_WOTS);
    p.set_tree_addr(wots_addr, w->geo.idx_tree);
    p.set_keypair_addr(wots_addr, w->geo.idx_leaf);

    // Do the work to generate the FORS signature (for the one FORS tree)
    p.fors_sign(signature, root, index, w->geo.fors[index], wots_addr);

    // Copy the FORS signature into where it goes
    // And, copy the root we computed to the work center
    // And, mark off this FORS signature as done (and check if that completes
    // the set)
    w->lock();
    memcpy( &w->fors_root[half][index*n], root, n );
    if (half == 0) {
        memcpy( w->sig + w->geo.fors_offset[index], signature, n * (fors_h+1) );
    }
    uint64_t done_so_far = w->fors_done[half] | ((uint64_t)1 << index);
    w->fors_done[half] = done_so_far;
    bool all_fors_trees_done = (done_so_far == w->fors_target);
    w->unlock();

    if (all_fors_trees_done) {
        // We just finished off the final FORS tree; hash them together to
        // come up with the FORS root
        level = half;
        hash_fors(w);
    }
}

//
// This is the task that generates the WOTS signature
void task::build_wots_sig(work_center *w) {
    // The level encodes both the WOTS tree level, and if we're the
    // primary or the secondary
    unsigned actual_level = level / 2;
    unsigned half = level & 1;

    key& p = *w->p;
    unsigned merkle_h = p.merkle_height();
    unsigned char wots_signature[ max_wots_bytes ]; 

    uint64_t tree_idx = shr( w->geo.idx_tree, merkle_h * actual_level );
    unsigned leaf_idx;
    if (actual_level == 0) {
        // Bottom tree - use the index generated from the message hash
        leaf_idx = w->geo.idx_leaf;
    } else {
        // Upper tree - extract the address from the tree index
        leaf_idx = (w->geo.idx_tree >> (merkle_h * (actual_level-1))) &
                    ((1 << merkle_h) - 1);
    }
    p.wots_sign( wots_signature, actual_level, tree_idx, leaf_idx,
                 w->merkle_root[half][actual_level] );

    // Copy it to where it is expected to be
    size_t sig_len = p.len_hash() * p.wots_digits(); // Length of the WOTS signature
    w->lock();
    if (w->wrote_wots & (1 << actual_level)) {
         // We already wrote the WOTS signature; check if we got
         // the same one
         if (0 == memcmp( w->sig + w->geo.wots[actual_level], wots_signature,
                          sig_len )) {
             // We got the same one - mark this level as double-checked
             w->validated_wots |= (1 << actual_level);
         } else {
             // Got something different - call a foul
             w->detected_fault = true;
             memset( w->sig + w->geo.wots[actual_level], 0, sig_len );
        }
    } else {
        // First time for this signature; write it out
        memcpy( w->sig + w->geo.wots[actual_level], wots_signature,
                sig_len );
        w->wrote_wots |= (1 << actual_level);
    }
    w->unlock();
}

//
// This is the task that hashes all the FORS results together
// This is a comparatively simple task (and doesn't involve AVX at all), but
// one that must come after all the FORS trees have been built
void task::hash_fors(work_center *w) {
    unsigned half = level;  // This is 0 for the primary, 1 for the secondary
    unsigned char hash_result[ max_len_hash ];
    key& p = *w->p;
    addr_t fors_pk_addr = { 0 };

    // Compute the root
    p.set_tree_addr(fors_pk_addr, w->geo.idx_tree);
    p.set_keypair_addr(fors_pk_addr, w->geo.idx_leaf);
    p.set_type(fors_pk_addr, ADDR_TYPE_FORSPK);
    p.thash(hash_result, w->fors_root[half], p.k(), fors_pk_addr);

    // Copy it to where it is expected to be
    w->lock();
    memcpy( w->merkle_root[half][0], hash_result, p.len_hash() );
    w->unlock();

    // Schedule it to be signed with the bottom WOTS signature
    set_task( &task::build_wots_sig, half );
    w->enqueue(this);
}

}  /* namespace sphincs_plus */
