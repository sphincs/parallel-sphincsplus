#if !defined(SPHINCSPLUS_API_H_)
#define SPHINCSPLUS_API_H_

///
/// \file api.h
/// \brief This is the public interface to the fast sphincs implementation

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <memory>            // For unique_ptr
#include "immintrin.h"

namespace sphincs_plus {

///
/// Flag that indicates whether an operation succeeded or failed
typedef bool success_flag;
const success_flag success = true;    /// Operation succeeded
const success_flag failure = false;   /// Operation failed

///
/// This is a function that provides randomness to us
/// We expect the application to provide this to us during key generation
/// and optionally during signing
/// @param[out] target The memory area to place randomness
/// @param[in]  num_bytes The number of bytes of randomness to write
/// \return success if we were able to generate the randomness
typedef success_flag (*random_function)( void *target, size_t num_bytes );

///
/// Flag that indicates whether the random class object succeeded or failed
/// It has a third option (random_default), that indicates to the caller that
/// on random function was provided by the application
enum random_return {
    random_failure,    //<! Random generator failed
    random_success,    //<! Random generator succeeded
    random_default     //<! No random generator provided
};

///
/// This is the class we invoke when we want randomness.
/// It is used as a parameter to the generate_key_pair and sign member
/// functions (both of which can use randomness)
///
/// It can be created in three ways:
/// - The application can just pass a pointer to a random_function to sign or
///   generate_key_pair, and the compiler will create a temporary random
///   object (which, when invoked, will just call the random_function).
/// - The application can pass a 0 to sign; the temporary random object will,
///   when involved, just return random_default, which will cause sign to
///   fall back to deterministic signatures.  Note that generate_key_pair
///   will fail if you pass it 0 - it always needs randomness
/// - The application can derive a child class with a redefined operator(),
///   and pass such an object.
class random {
    random_function func;
public:
    /// Ask the object for num_bytes random bytes
    /// @param[out]  target Where to place the random bytes
    /// @param[in]   num_bytes Number of bytes to ask for
    /// \return Whether we were able to provide the random bytes
    virtual enum random_return operator()( void *target,
                                           size_t num_bytes ) const;
    /// Create a random object based on a function that provides randomness
    /// @param[in] f  The random function.  0 means that no randomness was
    ///               provided and that the caller should fall back on the
    ///               default behavior (assuming that the class has not been
    ///               derived)
    random( random_function f = 0 ) : func(f) { ; }
};

/// This is a default random_function (should the application prefer not to
/// be bothered).  It uses the rdrand instruction to obtain its entropy
success_flag rdrand_fill( void *raget, size_t num_bytes );

///
/// We do hashes in several places within the Sphincs+ structure
/// This enum declares the reason for this specific hash
enum hash_reason {
    ADDR_TYPE_WOTS = 0,    //!< We're hashing as a part of a WOTS+ chain
    ADDR_TYPE_WOTSPK = 1,  //!< We're hashing all the WOTS+ chain tops
    ADDR_TYPE_HASHTREE = 2,//!< We're hashing within a Merkle tree
    ADDR_TYPE_FORSTREE = 3,//!< We're hashing wihtin a FORS tree
    ADDR_TYPE_FORSPK = 4   //!< We're generating a private FORS value
};

///
/// This is our designation of an 'address structure', called an ADRS structure
/// in the Sphincs+ documentation
/// It has nothing to do with IP addresses
typedef unsigned char addr_t[32];

struct digit;   // Used internally, some member functions refer to it
struct signature_geometry; // Ditto

///
/// A SHAKE256 intermediate state after some prefix has been hashed
struct SHAKE256_PRECOMPUTE {
    uint64_t s[25];   //<! The state of the SHAKE256 permutation
    unsigned index;   //<! The byte index where we absorb the next byte
    unsigned nonzero; //<! Number of nonzero (64 bit) words
};

///
/// Abstract class used to generate num_track leaf nodes
class leaf_gen {
public:
    /// This is the abstract function to generate the nodes
    /// Note that the number of nodes (and the size of the node) depends on
    /// the parameter set we're using - we expect the caller to know those
    /// @param[out] target Where to place the nodes (all consecutively)
    /// @param[in]  idx The index of the first node
    virtual void operator()(unsigned char* target,
                            uint32_t idx) = 0;
};

///
/// This is the base class for a Sphincs+ key (either public or private)
/// It can hold a private key (which allows you to sign or verify), a public
/// key (which only allows you to verify), or no key at all (if you haven't
/// assigned it a key quite yet).
/// We derive child classes for all 36 different parameter sets below
class key {
private:
    // The Sphincs+ geometry; this is private because we don't want
    // anyone reaching in and tweaking it after construction
    size_t len_hash_;
    size_t k_;
    size_t t_;
    size_t h_;
    size_t d_;
    size_t wots_digits_;
    size_t merkle_height_;
    size_t wots_bytes_;

    // The public/private keys
    unsigned char keys[ 4 * 32 ]; //<! This is our copy of the private key
                           //<! (or public key if we only have that)
    bool have_private_key; //<! Set if we have a private key
    bool have_public_key;  //<! Set if we have a public key

    unsigned num_thread;   //<! Number of threads we try to use while
                           //<! signing.  We allow the application to tell
                           //<! us what this should be

    bool detect_fault;     // Are we in fault detection mode?

    size_t initialize_geometry(struct signature_geometry& geo);
    void hash_message(struct signature_geometry& geo,
           const unsigned char *r,
           const unsigned char *message, size_t len_message );

protected:
    size_t len_hash(void) { return len_hash_; } //<! Hash size in bytes
    size_t k(void) { return k_; }  //<! Number of FORS trees
    size_t t(void) { return t_; }  //<! Depth of each FORS tree
    size_t h(void) { return h_; }  //<! Total height of hypertree
    size_t d(void) { return d_; }  //<! Number of Merkle trees in hypertree
    size_t wots_digits(void) { return wots_digits_; } //<! Number of WOTS digits
    size_t merkle_height(void) { return merkle_height_; } //<! Height of each
                                   //<! Merkle tree
    size_t wots_bytes(void) { return wots_bytes_; } //<! Length of a WOTS
                                   //<! signature

    const unsigned char *get_secret_seed(void); //<! Get the secret sauce we
                                   //<! use to generate our bottom level values
                                   //<! If the attacker learns this, all
                                   //<! security disappears
    const unsigned char *get_prf(void); //<! Get the secret value we use to
                                   //<! compute the PRF function.  If the
                                   //<! attacker learns this, he would be able
                                   //<! to perform a collision attack
    const unsigned char *get_public_seed(void); //<! Get the public value we
                                   //<! use to distinguish this public key.
                                   //<! Public knowledge
    const unsigned char *get_root(void); //<! Get the top level root value
                                   //<! Public knowledge

    /// These tell this object what geometry (e.g. the number and size of
    /// FORS trees and Merkle trees) this parameter set will be using
    /// It should be called only during construction
    void set_geometry( size_t len_hash, size_t k, size_t t, size_t h,
                       size_t d, size_t wots_digits );
    /// We're implementing a 128S parameter set
    void set_128s(void) { set_geometry( 16, 14, 12, 63,  7, 35 ); }
    /// We're implementing a 128F parameter set
    void set_128f(void) { set_geometry( 16, 33,  6, 66, 22, 35 ); }
    /// We're implementing a 192S parameter set
    void set_192s(void) { set_geometry( 24, 17, 14, 63,  7, 51 ); }
    /// We're implementing a 192F parameter set
    void set_192f(void) { set_geometry( 24, 33,  8, 66, 22, 51 ); }
    /// We're implementing a 256S parameter set
    void set_256s(void) { set_geometry( 32, 22, 14, 64,  8, 67 ); }
    /// We're implementing a 256F parameter set
    void set_256f(void) { set_geometry( 32, 35,  9, 68, 17, 67 ); }

    /// Generate a WOTS signature within the Sphincs+ signature
    /// @param[out] sig Where to place the signature
    /// @param[in] merkle_level The level of the Merkle tree is just
    ///     above this; 0 for bottommost
    /// @param[in] tree_idx Which Merkle tree is just above this; 0
    ///     for the leftmost 
    /// @param[in] leaf_idx Which bottom node of the Merkle tree is
    ///     resides under; 0 for the leftmost
    /// @param[in] message Message to sign (implicitly n bytes)
    void wots_sign( unsigned char *sig, unsigned merkle_level,
                    uint64_t tree_idx, unsigned leaf_idx,
                    const unsigned char *message );

    /// Generate a Merkle tree; optionally generate the
    /// authentication path from a specific node (idx_leaf)
    /// @param[out] sig Where to place the authentication path.  May be NULL
    ///                 if the caller does not need this.
    /// @param[out] root Where to place the value of the root node
    /// @param[in] wots_addr The address structure to pass to the WOTS+
    ///                 routines that generate the leaf nodes
    /// @param[in] tree_addr The partially initially address structure
    ///                 that'll be used to combine internal nodes
    /// @param[in] idx_leaf The index of the leaf (0 is leftmost) that
    ///                 we'll be generating the authentication path of.
    ///                 Also will be passed to the WOTS routines to indicate
    ///                 which WOTS+ siganture we'll generate
    /// @param[in] mode Allows us to generate the entire tree, or the left
    ///                 or right subtree directly underneath the root
    ///                 0 - Generate the entire tree
    ///                 1 - Generate the left subtree
    ///                 3 - Generate the right subtree
    void merkle_sign(uint8_t *sig, unsigned char *root,
                     addr_t wots_addr, addr_t tree_addr,
                     uint32_t idx_leaf, unsigned mode = 0);

    /// Generate a FORS tree, along with the authentication path
    /// @param[out] sig Where to place the authentication path
    /// @param[out] root Where to place the root node
    /// @param[in] which_fors_tree Which FORS tree are we generating (0 for
    ///                         the leftmost
    /// @param[in] idx_leaf The FORS leaf whose authentication path we're
    ///                  generating
    /// @param[in] fors_addr The address structure used to compute both
    ///                   the leaf FORS nodes and the internal nodes
    void fors_sign(uint8_t *sig, unsigned char *root,
                     unsigned which_fors_tree, uint32_t idx_leaf,
                     addr_t fors_addr );

    // The various tweakable hash functions (both single, and multitrack
    // versions ("_xn")
    /// Perform the Sphincs+ PRF function on the message
    /// @param[out] result Where to place the PRF function output
    /// @param[in] opt The optional randomness
    /// @param[in] msg The application-selected message
    /// @param[in] len_message The lenght of the message
    virtual void prf_msg( unsigned char *result,
              const unsigned char *opt,
              const unsigned char *msg, size_t len_msg ) = 0;
    /// Performs the Sphincs+ H_msg function on the message
    /// @param[out] result Where to place the H_msg function output
    /// @param[in] len_result The number of bytes of output to generate
    /// @param[in] r The randomess input
    /// @param[in] msg The application-selected message
    /// @param[in] len_message The lenght of the message
    virtual void h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) = 0;
    /// Performs the Sphincs+ F function on an array (size num_track) of
    /// inputs
    /// @param[out] out An array of pointers to locations to place the results
    ///               of the F functions
    /// @param[in] in An array of pointers to locations to get the inputs to
    ///               the F functions
    /// @param[in] addr An array of num_track address structures (no indirection
    ///               this time)
    virtual void f_xn(unsigned char **out, unsigned char **in, addr_t* addr);
    /// Performs the Sphincs+ T function on a single input
    /// @param[out] out Where to place the result of the T function
    /// @param[in] in The message input to the T function
    /// @param[in] inblocks The length (in n byte blocks) of the input
    /// @param[in] addr The address structure to use
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) = 0;
    /// Performs the Sphincs+ T function on an array (size num_track) of
    /// inputs
    /// @param[out] out An array of pointers to locations to place the results
    ///               of the F functions
    /// @param[in] in An array of pointers to locations to get the inputs to
    ///               the F functions
    /// @param[in] inblocks The length (in n byte blocks) of each input
    /// @param[in] addrxn An array of num_track address structures (no
    ///               indirection this time)
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn) = 0;
    /// Performs the Sphincs+ PRF function on an array (size num_track) of
    /// inputs
    /// @param[out] out An array of pointers to locations to place the results
    ///               of the PRF functions
    /// @param[in] addrxn An array of num_track address structures which are
    ///               the inputs
    virtual void prf_addr_xn(unsigned char **out,
              const addr_t* addrxn) = 0;

    /// Generate a Merkle tree (either FORS or WOTS+-based Merkle), computing
    /// the root node and optionally the authentication path
    /// @param[out] root Where to place the root node
    /// @param[out] auth_path Where to place the authentication path.  Can be
    ///                       NULL if no authentication path is required
    /// @param[in] idx_leaf The leaf whose authentication path we're
    ///                  generating.  ~0 if we're not generating any
    ///                  authentication path
    /// @param[in] idx_offset The offset to apply to the computed tree_indicies
    ///                  used when updating address structures
    /// @param[in] tree_height The number of tree levels to compute
    /// @param[in] leaf The leaf_gen object to use to generate the leaf hashes
    /// @param[in] tree_addrxn num_track address structures used when hashing
    ///                  internal nodes
    void treehashxn(unsigned char *root, unsigned char *auth_path,
                    uint32_t leaf_idx, uint32_t idx_offset,
                    uint32_t tree_height,
                    leaf_gen& leaf,
                    addr_t* tree_addrxn);

    /// This is the number of hashes we can compute in parallel
    virtual unsigned num_track(void) = 0;
    /// This is the log2 of the number of hashes we can compute in parallel
    virtual unsigned num_log_track(void) = 0;

    // Pointers into the addr structure that we use; SHA-256
    // uses a different (shorter) addr structure
    unsigned offset_layer, offset_tree, offset_type;
    unsigned offset_kp_addr1, offset_kp_addr2;
    unsigned offset_chain_addr, offset_hash_addr;
    unsigned offset_tree_hgt, offset_tree_index;

    // And the functions to set fields within the addr structure
    /// Set the layer address in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] layer The new layer address
    void set_layer_addr(addr_t addr, uint32_t layer) {
        addr[offset_layer] = layer;
    }
    /// Set the tree address in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] tree The new tree address
    void set_tree_addr(addr_t addr, uint64_t tree);
    /// Set the type field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] type The new hash type (reason)
    void set_type(addr_t  addr, enum hash_reason type) {
        addr[offset_type] = type;
    }
    /// Copy the layer and the tree fields in the address structure
    /// from one address structure to another
    /// @param[out] out The address structure to copy to
    /// @param[in] in The address structure to copy from
    void copy_subtree_addr(addr_t out, const addr_t in);
    /// Set the keypair field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] keypair The new keypair field 
    void set_keypair_addr(addr_t addr, uint32_t keypair);
    /// Set the chain address field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] chain The new chain address field 
    void set_chain_addr(addr_t addr, uint32_t chain) {
        addr[offset_chain_addr] = chain;
    }
    /// Set the hash address field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] hash The new hash address field 
    void set_hash_addr(addr_t addr, uint32_t hash) {
        addr[offset_hash_addr] = hash;
    }
    /// Set the tree height field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] tree_height The new tree height field 
    void set_tree_height(addr_t addr, uint32_t tree_height) {
        addr[offset_tree_hgt] = tree_height;
    }
    /// Set the tree index field in the address structure
    /// @param[out] addr The address structure to update
    /// @param[in] tree_index The new tree index field 
    void set_tree_index(addr_t  addr, uint32_t tree_index);
    /// Copy the layer, tree and keypair fields of the address structure.
    /// This is from one address structure to another
    /// @param[out] out The address structure to copy to
    /// @param[in] in The address structure to copy from
    void copy_keypair_addr(addr_t out, const addr_t in);

    /// Convert the message (n byte hash) from bytes into Winternitz digits.
    /// This also appends the checksum at the end
    /// @param[out] lengths Where the array of digits are written; there
    ///                     will be a total of wots_digits written
    /// @param[in] msg The hash to convert, exactly n bytes in length
    void chain_lengths(unsigned *lengths, const unsigned char *msg);

    /// This advances the wots hashes in the array the given number of WOTS
    /// positions as specified in the d_array
    /// @param[inout] array On entry, the array of initial hash values.
    ///               On return, the hash values after they have been advanced
    ///               d_array[i].count times
    /// @param[in] d_array The array giving instructions as to how advance
    ///               the various digits.  d_array[i].count gives the number
    ///               of times digit i will need to be advanced;
    ///               d_array[i].index will give the initial hash_addr for
    ///               the first time digit i is advanced (and every additional
    ///               time that digit is advanced, hash_address is incremented
    ///               by one.
    ///               Note that this array will be overwritten by
    ///               compute_chains
    /// @param[in] addr The array of the address structures used to advance
    ///               the various digits
    void compute_chains(unsigned char* array, struct digit* d_array,
                        addr_t* addr);

    friend class task;
    friend class work_center;
    friend class gen_wots_leaves;
    friend class gen_fors_leaves;

    /// Constructor that initializes the key object to the 'we have no
    /// public or private key' state
    key(void);
public:
    //
    // And the public API (the entire point of this)
 
    ///
    /// This will create a random public/private keypair
    /// @param[in] rand This is the random generator used.  If omitted, we'll
    ///                fall back to a default one
    /// \return success if we were able to generate the key pair
    success_flag generate_key_pair(const random& rand = rdrand_fill);

    /// Import a public key; the public key is assumed to be in the
    /// standard Sphincs+ format.  Since we're not importing with the
    /// private key, we won't be able to sign
    /// @param[in] public_key Pointer to the public key
 
    virtual void set_public_key(const unsigned char *public_key);
    /// Import a private key; the private key is assumed to be in the
    /// standard Sphincs+ format.
    /// @param[in] private_key Pointer to the private key
    virtual void set_private_key(const unsigned char *private_key);

    /// Get a copy of the public key.  Note that this returns a pointer
    /// to the golden image within the key, hence taking this pointer,
    /// casting it to nonconst and then writing through it is a Bad Idea
    /// \return The public key, or NULL if we don't have a public key
    const unsigned char *get_public_key(void);

    /// Get a copy of the private key.  It might seem like we shouldn't
    /// have an API to do this; however the application might need to write
    /// the private key to long term storage, so we kinda have to.
    /// Again, taking this pointer, casting it to nonconst and then writing
    /// through it is a Bad Idea
    /// \return The private key, or NULL if we don't have a public key
    const unsigned char *get_private_key(void);

    /// Generate a signature for a message using the private key installed in
    /// this object
    /// @param[out] signature Where to write the signature
    /// @param[in] len_signature_buffer The length of the signature buffer;
    ///            If the buffer is not long enough to receive the entire
    ///            signature, nothing will be written, and this will fail
    /// @param[in] message The message to sign
    /// @param[in] len_message The length of the message to sign
    /// @param[in] rand The object that returns the randomness used to generate
    ///            this signature.  If 0, this will fall back to determanistic
    ///            signature generation.  If omitted, this will fall back to
    ///            a default randomness generation function
    /// \return success (we generated the signature) or failure
    success_flag sign(
            unsigned char *signature, size_t len_signature_buffer,
            const unsigned char *message, size_t len_message,
            const random& rand = rdrand_fill);
 
    /// Generate a signature for a message using the private key installed in
    /// this object.  On failure, this throws an exception.
    /// @param[in] message The message to sign
    /// @param[in] len_message The length of the message to sign
    /// @param[in] rand The object that returns the randomness used to generate
    ///            this signature.  If 0, this will fall back to determanistic
    ///            signature generation.  If omitted, this will fall back to
    ///            a default randomness generation function
    /// \return The unique_ptr containing the signature
    std::unique_ptr<unsigned char[]> sign(
            const unsigned char *message, size_t len_message,
            const random& rand = rdrand_fill);

    /// Verify a signature that is alleged to be for the message, using the
    /// public key installed in this object.
    /// @param[in] signature The signature we're checking
    /// @param[in] len_signature The length of the signature
    /// @param[in] message THe message we're checking
    /// @param[in] len_message The length of the message
    /// \return Success (the signature checked out) or failure (it didn't or
    /// this key object doesn't have a public key to check)
    success_flag verify(
            const unsigned char *signature, size_t len_signature,
            const void *message, size_t len_message);

    /// Get the length of a signature with this parameter set
    /// \return The length of a signature
    size_t len_signature(void);

    /// Get the length of a public key with this parameter set
    /// \return The length of a public key
    size_t len_public_key(void);

    /// Get the length of a private key with this parameter set
    /// \return The length of a private key
    size_t len_private_key(void);

    /// Get the number of bytes of randomness used during the key
    /// generation process
    /// \return Bytes of randomness used
    size_t len_randomness(void) { return 3 * len_hash(); } // The amount of
                              // randomness the key generation process uses

    /// Set the suggested number of threads we should use when generating
    /// a signature.  We'll never use more than this number of threads; we may
    /// use fewer.
    /// n<=1 turns this into single threaded mode (we won't spawn any child
    /// threads).
    /// @param[in] n Try to use n threads.  This count includes the parent
    ///             thread
    void set_num_thread(unsigned n) { num_thread = n; }
    void set_fault_detection(bool flag) { detect_fault = flag; }

    virtual ~key(void);
};

///
/// This abstract class is for SHA256-based parameter sets
class sha256_hash : public key {
private:
    /// This precomputes the intermediate state of the public seed (so
    /// we don't have to recompute it everytime we need it).
    /// This is called whenever we update the public key (which includes
    /// updates of the private key)
    /// @param[in] public_seed The new public seed
    void initialize_public_seed(const unsigned char *public_seed);
protected:
    virtual void prf_addr_xn(unsigned char **out,
              const addr_t* addrxn);
    virtual void prf_msg( unsigned char *result,
              const unsigned char *opt,
              const unsigned char *msg, size_t len_msg );
    virtual void h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg );

    /// The prehashed public seed
    uint32_t state_seeded[8];

    virtual unsigned num_track(void);
    virtual unsigned num_log_track(void);

    sha256_hash(void);
public:
    virtual void set_public_key(const unsigned char *public_key);
    virtual void set_private_key(const unsigned char *private_key);
};

/// This abstract class is for SHAKE256-based parameter sets
class shake256_hash : public key {
protected:
    SHAKE256_PRECOMPUTE pre_pub_seed;  //!< The prehashed public seed
    SHAKE256_PRECOMPUTE pre_priv_seed; //!< The prehashed private seed

    virtual unsigned num_track(void);
    virtual unsigned num_log_track(void);

    virtual void prf_addr_xn(unsigned char **out,
              const addr_t* addrxn);
    virtual void prf_msg( unsigned char *result,
              const unsigned char *opt,
              const unsigned char *msg, size_t len_msg );
    virtual void h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg );
public:
    virtual void set_public_key(const unsigned char *public_key);
    virtual void set_private_key(const unsigned char *private_key);
    virtual ~shake256_hash();
};

/// This abstract class is for Haraka-based parameter sets
class haraka_hash : public key {
protected:
    __m128i pub_seed_expanded[40]; //<! Expanded Haraka public key
    __m128i priv_seed_expanded[40]; //<! Expanded Haraka private key

    virtual unsigned num_track(void);
    virtual unsigned num_log_track(void);

    virtual void prf_addr_xn(unsigned char **out,
              const addr_t* addrxn);
    virtual void prf_msg( unsigned char *result,
              const unsigned char *opt,
              const unsigned char *msg, size_t len_msg );
    virtual void h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg );
        // This will need to be defined by the subclass
    virtual void f_xn(unsigned char **out, unsigned char **in, addr_t* addrxn) = 0;
public:
    virtual void set_public_key(const unsigned char *public_key);
    virtual void set_private_key(const unsigned char *private_key);
    virtual ~haraka_hash(); // To zeroize priv_seed_expanded
};

/// This abstract class is for SHA256-simple-based parameter sets
class key_sha256_simple : public sha256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

/// This abstract class is for SHA256-robust-based parameter sets
class key_sha256_robust : public sha256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t  addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

/// This abstract class is for SHAKE256-simple-based parameter sets
class key_shake256_simple : public shake256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t  addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

/// This abstract class is for SHAKE256-robust-based parameter sets
class key_shake256_robust : public shake256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

/// This abstract class is for Haraka-simple-based parameter sets
class key_haraka_simple : public haraka_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addr);
    virtual void f_xn(unsigned char **out, unsigned char **in,
             addr_t* addrxn);
};

/// This abstract class is for Haraka-robust-based parameter sets
class key_haraka_robust : public haraka_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
    virtual void f_xn(unsigned char **out, unsigned char **in,
             addr_t* addrxn);
};

//
// And now the individual parameter set classes

/// The class for keys with the SHA256 simple 128F parameter set
class key_sha256_128f_simple : public key_sha256_simple {
public:
    key_sha256_128f_simple(void) { set_128f(); }
};

/// The class for keys with the SHA256 robust 128F parameter set
class key_sha256_128f_robust : public key_sha256_robust {
public:
    key_sha256_128f_robust(void) { set_128f(); }
};

/// The class for keys with the SHA256 simple 128S parameter set
class key_sha256_128s_simple : public key_sha256_simple {
public:
    key_sha256_128s_simple(void) { set_128s(); }
};

/// The class for keys with the SHA256 robust 128S parameter set
class key_sha256_128s_robust : public key_sha256_robust {
public:
    key_sha256_128s_robust(void) { set_128s(); }
};

/// The class for keys with the SHA256 simple 192F parameter set
class key_sha256_192f_simple : public key_sha256_simple {
public:
    key_sha256_192f_simple(void) { set_192f(); }
};

/// The class for keys with the SHA256 robust 192F parameter set
class key_sha256_192f_robust : public key_sha256_robust {
public:
    key_sha256_192f_robust(void) { set_192f(); }
};

/// The class for keys with the SHA256 simple 192S parameter set
class key_sha256_192s_simple : public key_sha256_simple {
public:
    key_sha256_192s_simple(void) { set_192s(); }
};

/// The class for keys with the SHA256 robust 192S parameter set
class key_sha256_192s_robust : public key_sha256_robust {
public:
    key_sha256_192s_robust(void) { set_192s(); }
};

/// The class for keys with the SHA256 simple 256F parameter set
class key_sha256_256f_simple : public key_sha256_simple {
public:
    key_sha256_256f_simple(void) { set_256f(); }
};

/// The class for keys with the SHA256 robust 256F parameter set
class key_sha256_256f_robust : public key_sha256_robust {
public:
    key_sha256_256f_robust(void) { set_256f(); }
};

/// The class for keys with the SHA256 simple 256S parameter set
class key_sha256_256s_simple : public key_sha256_simple {
public:
    key_sha256_256s_simple(void) { set_256s(); }
};

/// The class for keys with the SHA256 robust 256S parameter set
class key_sha256_256s_robust : public key_sha256_robust {
public:
    key_sha256_256s_robust(void) { set_256s(); }
};

/// The class for keys with the SHAKE256 simple 128F parameter set
class key_shake256_128f_simple : public key_shake256_simple {
public:
    key_shake256_128f_simple(void) { set_128f(); }
};

/// The class for keys with the SHAKE256 robust 128F parameter set
class key_shake256_128f_robust : public key_shake256_robust {
public:
    key_shake256_128f_robust(void) { set_128f(); }
};

/// The class for keys with the SHAKE256 simple 128S parameter set
class key_shake256_128s_simple : public key_shake256_simple {
public:
    key_shake256_128s_simple(void) { set_128s(); }
};

/// The class for keys with the SHAKE256 robust 128S parameter set
class key_shake256_128s_robust : public key_shake256_robust {
public:
    key_shake256_128s_robust(void) { set_128s(); }
};

/// The class for keys with the SHAKE256 simple 192F parameter set
class key_shake256_192f_simple : public key_shake256_simple {
public:
    key_shake256_192f_simple(void) { set_192f(); }
};

/// The class for keys with the SHAKE256 robust 192F parameter set
class key_shake256_192f_robust : public key_shake256_robust {
public:
    key_shake256_192f_robust(void) { set_192f(); }
};

/// The class for keys with the SHAKE256 simple 192S parameter set
class key_shake256_192s_simple : public key_shake256_simple {
public:
    key_shake256_192s_simple(void) { set_192s(); }
};

/// The class for keys with the SHAKE256 robust 192S parameter set
class key_shake256_192s_robust : public key_shake256_robust {
public:
    key_shake256_192s_robust(void) { set_192s(); }
};

/// The class for keys with the SHAKE256 simple 256F parameter set
class key_shake256_256f_simple : public key_shake256_simple {
public:
    key_shake256_256f_simple(void) { set_256f(); }
};

/// The class for keys with the SHAKE256 robust 256F parameter set
class key_shake256_256f_robust : public key_shake256_robust {
public:
    key_shake256_256f_robust(void) { set_256f(); }
};

/// The class for keys with the SHAKE256 simple 256S parameter set
class key_shake256_256s_simple : public key_shake256_simple {
public:
    key_shake256_256s_simple(void) { set_256s(); }
};

/// The class for keys with the SHAKE256 robust 256S parameter set
class key_shake256_256s_robust : public key_shake256_robust {
public:
    key_shake256_256s_robust(void) { set_256s(); }
};

/// The class for keys with the HARAKA simple 128F parameter set
class key_haraka_128f_simple : public key_haraka_simple {
public:
    key_haraka_128f_simple(void) { set_128f(); }
};

/// The class for keys with the HARAKA robust 128F parameter set
class key_haraka_128f_robust : public key_haraka_robust {
public:
    key_haraka_128f_robust(void) { set_128f(); }
};

/// The class for keys with the HARAKA simple 128S parameter set
class key_haraka_128s_simple : public key_haraka_simple {
public:
    key_haraka_128s_simple(void) { set_128s(); }
};

/// The class for keys with the HARAKA robust 128S parameter set
class key_haraka_128s_robust : public key_haraka_robust {
public:
    key_haraka_128s_robust(void) { set_128s(); }
};

/// The class for keys with the HARAKA simple 192F parameter set
class key_haraka_192f_simple : public key_haraka_simple {
public:
    key_haraka_192f_simple(void) { set_192f(); }
};

/// The class for keys with the HARAKA robust 192F parameter set
class key_haraka_192f_robust : public key_haraka_robust {
public:
    key_haraka_192f_robust(void) { set_192f(); }
};

/// The class for keys with the HARAKA simple 192S parameter set
class key_haraka_192s_simple : public key_haraka_simple {
public:
    key_haraka_192s_simple(void) { set_192s(); }
};

/// The class for keys with the HARAKA robust 192S parameter set
class key_haraka_192s_robust : public key_haraka_robust {
public:
    key_haraka_192s_robust(void) { set_192s(); }
};

/// The class for keys with the HARAKA simple 256F parameter set
class key_haraka_256f_simple : public key_haraka_simple {
public:
    key_haraka_256f_simple(void) { set_256f(); }
};

/// The class for keys with the HARAKA robust 256F parameter set
class key_haraka_256f_robust : public key_haraka_robust {
public:
    key_haraka_256f_robust(void) { set_256f(); }
};

/// The class for keys with the HARAKA simple 256S parameter set
class key_haraka_256s_simple : public key_haraka_simple {
public:
    key_haraka_256s_simple(void) { set_256s(); }
};

/// The class for keys with the HARAKA robust 256S parameter set
class key_haraka_256s_robust : public key_haraka_robust {
public:
    key_haraka_256s_robust(void) { set_256s(); }
};

}  /* namespace sphincs_plus */

#endif /* SPHINCSPLUS_API_H_ */
