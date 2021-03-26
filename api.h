#if !defined(SPHINCSPLUS_API_H_)
#define SPHINCSPLUS_API_H_

//
// This is the application visible interface to the 'fast sphincs'
// implementation
//

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <memory>            // For unique_ptr
#include "immintrin.h"

namespace sphincs_plus {

//
// This defines the convention we use to report success/failure
// It is currently set to my preference (type bool, true==success),
// however I have it here to make it easy to change
typedef bool success_flag;
const success_flag success = true;
const success_flag failure = false;

//
// This is a function that provides randomness to us
// We expect the application to provide this to us during key generation
// and optionally during signing
typedef success_flag (*random_function)( void *target, size_t num_bytes );

// Here is a default one (should the application prefer not to be bothered)
success_flag rdrand_fill( void *raget, size_t num_bytes );

//
// We do hashes in several places within the Sphincs+ structure
// This enum declares the reason for this specific hash
enum hash_reason {
    ADDR_TYPE_WOTS = 0,
    ADDR_TYPE_WOTSPK = 1,
    ADDR_TYPE_HASHTREE = 2,
    ADDR_TYPE_FORSTREE = 3,
    ADDR_TYPE_FORSPK = 4
};

//
// This is our designation of an 'address structure', called an ADRS structure
// in the Sphincs+ documentation
// It has nothing to do with IP addresses
typedef unsigned char addr_t[32];

struct digit;   // Used internally, some member functions refer to it
struct signature_geometry; // Ditto

//
// A SHAKE256 state after some prefix has been hashed
struct SHAKE256_PRECOMPUTE {
    uint64_t s[25];
    unsigned index;
    unsigned nonzero;
};

//
// This is the base class for a Sphincs+ parameter set
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
    unsigned char keys[ 4 * 32 ];  // 32 is the largest hash we support
    bool have_private_key;
    bool have_public_key;

    unsigned num_thread;   // Number of threads we try to use while
                           // signing

    bool detect_fault;     // Are we in fault detection mode?

    size_t initialize_geometry(struct signature_geometry& geo);
    void hash_message(struct signature_geometry& geo,
           const unsigned char *r,
           const unsigned char *message, size_t len_message );

protected:
    size_t len_hash(void) { return len_hash_; } // Hash size in bytes
    size_t k(void) { return k_; }  // Number of FORS trees
    size_t t(void) { return t_; }  // Depth of each FORS tree
    size_t h(void) { return h_; }  // Total height of hypertree
    size_t d(void) { return d_; }  // Number of Merkle trees in hypertree
    size_t wots_digits(void) { return wots_digits_; } // Number of WOTS digits
    size_t merkle_height(void) { return merkle_height_; } // Height of each
                                   // Merkle tree
    size_t wots_bytes(void) { return wots_bytes_; } // Length of a WOTS
                                   // signature

    const unsigned char *get_secret_seed(void);
    const unsigned char *get_prf(void);
    const unsigned char *get_public_seed(void);
    const unsigned char *get_root(void);

    // These tell this object what geometry (e.g. the number and size of
    // FORS trees and Merkle trees) this parameter set will be using
    // It should be called only during construction
    void set_geometry( size_t len_hash, size_t k, size_t t, size_t h,
                       size_t d, size_t wots_digits );
    void set_128s(void) { set_geometry( 16, 14, 12, 63,  7, 35 ); }
    void set_128f(void) { set_geometry( 16, 33,  6, 66, 22, 35 ); }
    void set_192s(void) { set_geometry( 24, 17, 14, 63,  7, 51 ); }
    void set_192f(void) { set_geometry( 24, 33,  8, 66, 22, 51 ); }
    void set_256s(void) { set_geometry( 32, 22, 14, 64,  8, 67 ); }
    void set_256f(void) { set_geometry( 32, 35,  9, 68, 17, 67 ); }

    // Generate a WOTS signature
    void wots_sign( unsigned char *sig, unsigned merkle_level,
                    uint64_t tree_idx, unsigned leaf_idx,
                    const unsigned char *message );
    // Generate a Merkle tree; optionally generate the
    // authentication path from a specific node (idx_leaf)
    void merkle_sign(uint8_t *sig, unsigned char *root,
                     addr_t wots_addr, addr_t tree_addr,
                     uint32_t idx_leaf, unsigned mode = 0);
    // Generate a FORS tree, along with the authentication path
    void fors_sign(uint8_t *sig, unsigned char *root,
                     unsigned which_fors_tree, uint32_t idx_leaf,
                     addr_t wots_addr );

    // The various tweakable hash functions (both single, and multitrack
    // versions ("_xn")
    virtual void prf_msg( unsigned char *result,
              const unsigned char *opt,
              const unsigned char *msg, size_t len_msg ) = 0;
    virtual void h_msg( unsigned char *result, size_t len_result,
              const unsigned char *r,
              const unsigned char *msg, size_t len_msg ) = 0;
    virtual void f_xn(unsigned char **out, unsigned char **in, addr_t* addr);
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr) = 0;
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn) = 0;
    virtual void prf_addr_xn(unsigned char **out,
              const addr_t* addrxn) = 0;
    void treehashxn(unsigned char *root, unsigned char *auth_path,
                    uint32_t leaf_idx, uint32_t idx_offset,
                    uint32_t tree_height,
                    void (key::*gen_leafxn)(
                        unsigned char* /* Where to write the leaves */,
                        uint32_t idx, void *info),
                    addr_t* tree_addrxn,
                    void *info);
    void wots_gen_leafxn(unsigned char*,
                    uint32_t idx, void *info);
    void fors_gen_leafxn(unsigned char*,
                    uint32_t idx, void *info);

    virtual unsigned num_track(void) = 0;
    virtual unsigned num_log_track(void) = 0;

    // Pointers into the addr structure that we use; SHA-256
    // uses a different (shorter) addr structure
    unsigned offset_layer, offset_tree, offset_type;
    unsigned offset_kp_addr1, offset_kp_addr2;
    unsigned offset_chain_addr, offset_hash_addr;
    unsigned offset_tree_hgt, offset_tree_index;

    // And the functions to set fields within the addr structure
    void set_layer_addr(addr_t addr, uint32_t layer) {
        addr[offset_layer] = layer;
    }
    void set_tree_addr(addr_t addr, uint64_t tree);
    void set_type(addr_t  addr, enum hash_reason type) {
        addr[offset_type] = type;
    }
    void copy_subtree_addr(addr_t out, const addr_t in);
    void set_keypair_addr(addr_t addr, uint32_t keypair);
    void set_chain_addr(addr_t addr, uint32_t chain) {
        addr[offset_chain_addr] = chain;
    }
    void set_hash_addr(addr_t addr, uint32_t hash) {
        addr[offset_hash_addr] = hash;
    }
    void set_tree_height(addr_t addr, uint32_t tree_height) {
        addr[offset_tree_hgt] = tree_height;
    }
    void set_tree_index(addr_t  addr, uint32_t tree_index);
    void copy_keypair_addr(addr_t out, const addr_t in);

    void chain_lengths(unsigned *lengths, const unsigned char *msg);
    void compute_chains(unsigned char *array, struct digit *d_array,
                        addr_t* addr);

    friend class task;
    friend class work_center;

    key(void);
public:
    //
    // And the public API (the entire point of this)
    success_flag generate_key_pair(random_function rand = rdrand_fill);
    virtual void set_public_key(const unsigned char *public_key);
    virtual void set_private_key(const unsigned char *private_key);
    const unsigned char *get_public_key(void);
    const unsigned char *get_private_key(void);  // In case it needs to be
                                                 // written to disk

    success_flag sign(
            unsigned char *signature, size_t len_signature_buffer,
            const unsigned char *message, size_t len_message,
	    random_function rand = rdrand_fill);
    std::unique_ptr<unsigned char[]> sign(
            const unsigned char *message, size_t len_message,
	    random_function rand = rdrand_fill);
    success_flag verify(
            const unsigned char *signature, size_t len_signature,
            const void *message, size_t len_message);
    size_t len_signature(void);
    size_t len_public_key(void);
    size_t len_private_key(void);
    size_t len_randomness(void) { return 3 * len_hash(); } // The amount of
                              // randomness the key generation process uses

    void set_num_thread(unsigned n) { num_thread = n; }
    void set_fault_detection(bool flag) { detect_fault = flag; }

    virtual ~key(void);
};

// This is for SHA256-based parameter sets
class sha256_hash : public key {
private:
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
    uint32_t state_seeded[8]; // The prehashed public seed

    virtual unsigned num_track(void);
    virtual unsigned num_log_track(void);

    sha256_hash(void);
public:
    virtual void set_public_key(const unsigned char *public_key);
    virtual void set_private_key(const unsigned char *private_key);
};

// This is for SHAKE256-based parameter sets
class shake256_hash : public key {
protected:
    SHAKE256_PRECOMPUTE pre_pub_seed;  // The prehashed public seed
    SHAKE256_PRECOMPUTE pre_priv_seed; // The prehashed private seed

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

// This is for Haraka-based parameter sets
class haraka_hash : public key {
protected:
    __m128i pub_seed_expanded[40]; // Expanded Haraka keys (which are
    __m128i priv_seed_expanded[40]; // key dependent)

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
    virtual ~haraka_hash(); // To zeroize priv_seed_expanded,
};

// This is for SHA256-simple-based parameter sets
class key_sha256_simple : public sha256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

// This is for SHA256-robust-based parameter sets
class key_sha256_robust : public sha256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t  addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

// This is for SHAKE256-simple-based parameter sets
class key_shake256_simple : public shake256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t  addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

// This is for SHAKE256-robust-based parameter sets
class key_shake256_robust : public shake256_hash {
protected:
    virtual void thash(unsigned char *out,
             const unsigned char *in,
             unsigned int inblocks, addr_t addr);
    virtual void thash_xn(unsigned char **out,
             unsigned char **in, 
             unsigned int inblocks, addr_t* addrxn);
};

// This is for Haraka-simple-based parameter sets
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

// This is for Haraka-robust-based parameter sets
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

// The SHA256 simple 128F parameter set
class key_sha256_128f_simple : public key_sha256_simple {
public:
    key_sha256_128f_simple(void) { set_128f(); }
};

// The SHA256 robust 128F parameter set
class key_sha256_128f_robust : public key_sha256_robust {
public:
    key_sha256_128f_robust(void) { set_128f(); }
};

// The SHA256 simple 128S parameter set
class key_sha256_128s_simple : public key_sha256_simple {
public:
    key_sha256_128s_simple(void) { set_128s(); }
};

// The SHA256 robust 128S parameter set
class key_sha256_128s_robust : public key_sha256_robust {
public:
    key_sha256_128s_robust(void) { set_128s(); }
};

// The SHA256 simple 192F parameter set
class key_sha256_192f_simple : public key_sha256_simple {
public:
    key_sha256_192f_simple(void) { set_192f(); }
};

// The SHA256 robust 192F parameter set
class key_sha256_192f_robust : public key_sha256_robust {
public:
    key_sha256_192f_robust(void) { set_192f(); }
};

// The SHA256 simple 192S parameter set
class key_sha256_192s_simple : public key_sha256_simple {
public:
    key_sha256_192s_simple(void) { set_192s(); }
};

// The SHA256 robust 192S parameter set
class key_sha256_192s_robust : public key_sha256_robust {
public:
    key_sha256_192s_robust(void) { set_192s(); }
};

// The SHA256 simple 256F parameter set
class key_sha256_256f_simple : public key_sha256_simple {
public:
    key_sha256_256f_simple(void) { set_256f(); }
};

// The SHA256 robust 256F parameter set
class key_sha256_256f_robust : public key_sha256_robust {
public:
    key_sha256_256f_robust(void) { set_256f(); }
};

// The SHA256 simple 256S parameter set
class key_sha256_256s_simple : public key_sha256_simple {
public:
    key_sha256_256s_simple(void) { set_256s(); }
};

// The SHA256 robust 256S parameter set
class key_sha256_256s_robust : public key_sha256_robust {
public:
    key_sha256_256s_robust(void) { set_256s(); }
};

// The SHAKE256 simple 128F parameter set
class key_shake256_128f_simple : public key_shake256_simple {
public:
    key_shake256_128f_simple(void) { set_128f(); }
};

// The SHAKE256 robust 128F parameter set
class key_shake256_128f_robust : public key_shake256_robust {
public:
    key_shake256_128f_robust(void) { set_128f(); }
};

// The SHAKE256 simple 128S parameter set
class key_shake256_128s_simple : public key_shake256_simple {
public:
    key_shake256_128s_simple(void) { set_128s(); }
};

// The SHAKE256 robust 128S parameter set
class key_shake256_128s_robust : public key_shake256_robust {
public:
    key_shake256_128s_robust(void) { set_128s(); }
};

// The SHAKE256 simple 192F parameter set
class key_shake256_192f_simple : public key_shake256_simple {
public:
    key_shake256_192f_simple(void) { set_192f(); }
};

// The SHAKE256 robust 192F parameter set
class key_shake256_192f_robust : public key_shake256_robust {
public:
    key_shake256_192f_robust(void) { set_192f(); }
};

// The SHAKE256 simple 192S parameter set
class key_shake256_192s_simple : public key_shake256_simple {
public:
    key_shake256_192s_simple(void) { set_192s(); }
};

// The SHAKE256 robust 192S parameter set
class key_shake256_192s_robust : public key_shake256_robust {
public:
    key_shake256_192s_robust(void) { set_192s(); }
};

// The SHAKE256 simple 256F parameter set
class key_shake256_256f_simple : public key_shake256_simple {
public:
    key_shake256_256f_simple(void) { set_256f(); }
};

// The SHAKE256 robust 256F parameter set
class key_shake256_256f_robust : public key_shake256_robust {
public:
    key_shake256_256f_robust(void) { set_256f(); }
};

// The SHAKE256 simple 256S parameter set
class key_shake256_256s_simple : public key_shake256_simple {
public:
    key_shake256_256s_simple(void) { set_256s(); }
};

// The SHAKE256 robust 256S parameter set
class key_shake256_256s_robust : public key_shake256_robust {
public:
    key_shake256_256s_robust(void) { set_256s(); }
};

// The Haraka simple 128F parameter set
class key_haraka_128f_simple : public key_haraka_simple {
public:
    key_haraka_128f_simple(void) { set_128f(); }
};

// The Haraka robust 128F parameter set
class key_haraka_128f_robust : public key_haraka_robust {
public:
    key_haraka_128f_robust(void) { set_128f(); }
};

// The Haraka simple 128S parameter set
class key_haraka_128s_simple : public key_haraka_simple {
public:
    key_haraka_128s_simple(void) { set_128s(); }
};

// The Haraka robust 128S parameter set
class key_haraka_128s_robust : public key_haraka_robust {
public:
    key_haraka_128s_robust(void) { set_128s(); }
};

// The Haraka simple 192F parameter set
class key_haraka_192f_simple : public key_haraka_simple {
public:
    key_haraka_192f_simple(void) { set_192f(); }
};

// The Haraka robust 192F parameter set
class key_haraka_192f_robust : public key_haraka_robust {
public:
    key_haraka_192f_robust(void) { set_192f(); }
};

// The Haraka simple 192S parameter set
class key_haraka_192s_simple : public key_haraka_simple {
public:
    key_haraka_192s_simple(void) { set_192s(); }
};

// The Haraka robust 192S parameter set
class key_haraka_192s_robust : public key_haraka_robust {
public:
    key_haraka_192s_robust(void) { set_192s(); }
};

// The Haraka simple 256F parameter set
class key_haraka_256f_simple : public key_haraka_simple {
public:
    key_haraka_256f_simple(void) { set_256f(); }
};

// The Haraka robust 256F parameter set
class key_haraka_256f_robust : public key_haraka_robust {
public:
    key_haraka_256f_robust(void) { set_256f(); }
};

// The Haraka simple 256S parameter set
class key_haraka_256s_simple : public key_haraka_simple {
public:
    key_haraka_256s_simple(void) { set_256s(); }
};

// The Haraka robust 256S parameter set
class key_haraka_256s_robust : public key_haraka_robust {
public:
    key_haraka_256s_robust(void) { set_256s(); }
};

}  /* namespace sphincs_plus */

#endif /* SPHINCSPLUS_API_H_ */
