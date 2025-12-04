#include <stdint.h>
#include <stdlib.h>
#include <cstring>
#include "immintrin.h"
#include "shake256avx512.h"

namespace slh_dsa {

typedef __m512i u512;

//
// Design note: we split the state into separate rate and capacity elements
// In the absorb/squeeze logic, we keep the rate portion of the
// state as 8 separate 136 byte arrays concatinated together, with the
// capacity portion of the state in AVX-512 format, where each m512 contains
// a 64 bit 'lane' (FIPS 202 terminology, sorry, it conflicts with our use
// of lane) from each of the 8 lanes (our meaning).
// But, while we are processing the permutation, we convert the rate into an
// AVX-512 format (the capacity is already in that format).
// An alternative design would be to keep everything in AVX-512 format;
// however that would complicate (and more importantly, slow down) the 
// absorb/squeeze logic, and we expect that would slow down things more than
// doing a conversion when needed (which can use the AVX-512 instructions)
//
// This design makes it hard to adapt to different rates; as written, 
// it assumes a rate of 1088, which is what SHAKE-256 (and SHA3-256) uses.
// Changing this for different rates would be nontrivial

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

//
// Utility to xor in dest into src
static void memxor( unsigned char *dest,
                    unsigned char *src,
                    unsigned count ) {
    while (count >= sizeof(uint64_t)) {
        // The CPU handles unaligned accesses
        *(uint64_t *)dest ^= *(uint64_t *)src;
        dest += sizeof(uint64_t);
        src += sizeof(uint64_t);
        count -= sizeof(uint64_t);
    }
    while (count) {
        *dest++ ^= *src++;
        count--;
    }
}


#define ROL(x, y) _mm512_rol_epi64(x, y)

#define AT  _MM_TERNLOG_A
#define BT  _MM_TERNLOG_B
#define CT  _MM_TERNLOG_C

static void convert_rate_into_avx_format( u512 m[17], unsigned char in[8][136] ) {

    u512 c = _mm512_set_epi64(
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff);
    __v8di v10325476 = { 1, 0, 3, 2, 5, 4, 7, 6 };
    for (unsigned k=0; k<2; k++) {
        for (unsigned i=0; i<4; i++) {
            u512 t = _mm512_loadu_si512((__m512i *)( &in[2*i][64*k] ));
            u512 tr = __builtin_shuffle(t, v10325476 );
            u512 u = _mm512_loadu_si512((__m512i *)( &in[2*i+1][64*k] ));
            u512 ur = __builtin_shuffle(u, v10325476 );
            t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
            m[2*i + 8*k] = t;
            u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
            m[2*i+1+8*k] = u;
        }
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v23016745 = { 2, 3, 0, 1, 6, 7, 4, 5 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~1);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v23016745 );
        u512 u = m[j+2];
        u512 ur = __builtin_shuffle(u, v23016745 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+2] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~3);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v45670123 );
        u512 u = m[j+4];
        u512 ur = __builtin_shuffle(u, v45670123 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+4] = u;
    }

    /* And fit in the last (the 17th) m512 */
    m[16] = _mm512_set_epi64(
                *(uint64_t*)&in[7][128], 
                *(uint64_t*)&in[6][128], 
                *(uint64_t*)&in[5][128], 
                *(uint64_t*)&in[4][128], 
                *(uint64_t*)&in[3][128], 
                *(uint64_t*)&in[2][128], 
                *(uint64_t*)&in[1][128], 
                *(uint64_t*)&in[0][128]);
}

static void convert_avx_format_into_rate( unsigned char out[8][136], u512 m[17] ) {
    u512 c;

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v45670123 = { 4, 5, 6, 7, 0, 1, 2, 3 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~3);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v45670123 );
        u512 u = m[j+4];
        u512 ur = __builtin_shuffle(u, v45670123 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+4] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff,
        0x0000000000000000, 0x0000000000000000,
        0xffffffffffffffff, 0xffffffffffffffff);
    __v8di v23016745 = { 2, 3, 0, 1, 6, 7, 4, 5 };
    for (unsigned i=0; i<8; i++) {
        int j = i + (i&~1);
        u512 t = m[j];
        u512 tr = __builtin_shuffle(t, v23016745 );
        u512 u = m[j+2];
        u512 ur = __builtin_shuffle(u, v23016745 );
        t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
        m[j] = t;
        u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
        m[j+2] = u;
    }

    c = _mm512_set_epi64(
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff,
        0x0000000000000000, 0xffffffffffffffff);
    __v8di v10325476 = { 1, 0, 3, 2, 5, 4, 7, 6 };
    for (unsigned k=0; k<2; k++) {
        for (unsigned i=0; i<4; i++) {
            u512 t = m[2*i + 8*k];
            u512 tr = __builtin_shuffle(t, v10325476 );
            u512 u = m[2*i+1+8*k];
            u512 ur = __builtin_shuffle(u, v10325476 );
            t = _mm512_ternarylogic_epi64(c,t,ur,(~AT&CT) | (AT&BT));
            _mm512_storeu_si512( (__m512i *)( &out[2*i][64*k] ), t );
            u = _mm512_ternarylogic_epi64(c,u,tr,(~AT&BT) | (AT&CT));
            _mm512_storeu_si512( (__m512i *)( &out[2*i+1][64*k] ), u );
        }
    }

    /* And copy out the last (the 17th) m512 */
    uint64_t buffer[8];
    _mm512_storeu_si512( (__m512i *)( buffer ), m[16] );
    for (int i=0; i<8; i++) {
        *(uint64_t*)&out[i][128] = buffer[ i ];
    }
}

void SHAKE256_8x_CTX::init(void) {
    cur = 0;                   /* We're starting at the beginning */
    initial = 1;               /* We haven't permutted yet */
    phase = absorbing;
}

void SHAKE256_8x_CTX::update(unsigned char *d[8], unsigned len) {
    unsigned index = 0;
    if (initial) {
        unsigned this_chunk = rate - cur;
        if (this_chunk > len) this_chunk = len;
        for (int lane=0; lane<8; lane++) {
            memcpy( &s[lane][cur], d[lane], this_chunk );
        }
        index += this_chunk;
        cur += this_chunk;
        len -= this_chunk;
        if (cur == rate) {
            reset_initial();
            permute();
            cur = 0;
        }
    }
    while (len) {
        unsigned this_chunk = rate - cur;
        if (this_chunk > len) this_chunk = len;
        for (int lane=0; lane<8; lane++) {
            memxor( &s[lane][cur], &d[lane][index], this_chunk );
        }
        index += this_chunk;
        cur += this_chunk;
        len -= this_chunk;
        if (cur == rate) {
            permute();
            cur = 0;
        }
    }
}

//
// This takes us out of initial mode, clearing the elements that
// haven't been touched 
void SHAKE256_8x_CTX::reset_initial(void) {
    if (!initial) return;
    for (int lane=0; lane<8; lane++) {
        memset( &s[lane][cur], 0, rate - cur );
    }
    initial = 0;

    // Clear out the capacity
    u512 zero = _mm512_set1_epi64(0);
    for (unsigned j=0; j < capacity; j++) {
        cap[j] = zero;
    }
}

void SHAKE256_8x_CTX::squeeze(unsigned char *out[8], unsigned len) {
    if (phase == absorbing) {
        reset_initial();
            // Include the padding
        for (int lane=0; lane<8; lane++) {
            s[lane][cur]    ^= 0x1F;  // 0x1F == SHAKE-256
            s[lane][rate-1] ^= 0x80;
        }

        permute();

        cur = 0;          // And reset for the squeezing
        phase = squeezing;
    }

    unsigned index = 0;
  
    while (len) {
        if (cur == rate) {
                // Actually, we never hit this, because SLH-DSA never asks
                // to squeeze this much
            permute();
            cur = 0;
        }
        unsigned this_chunk = rate - cur;
        if (this_chunk > len) this_chunk = len;
        for (int lane=0; lane<8; lane++) {
            memcpy( &out[lane][index], &s[lane][cur], this_chunk );
        }
        index += this_chunk;
        cur += this_chunk;
        len -= this_chunk;
    }
}

static u512 XOR2( u512 a, u512 b ) {
    return _mm512_ternarylogic_epi64( a, b, a, AT^BT ); // The third parameter is ignored
}

static u512 XOR3( u512 a, u512 b, u512 c ) {
    return _mm512_ternarylogic_epi64( a, b, c, AT^BT^CT );
}

static u512 XOR5( u512 a, u512 b, u512 c, u512 d, u512 e) {
    return XOR3( a, b, XOR3( c, d, e ) );
}

void SHAKE256_8x_CTX::permute(void) {
    u512 rate_in_avx_format[8*rate / 64];

    // One potential optimization would be, if we're re-permuting in the
    // squeeze phase, don't reconvert the rate (as it's exactly the same
    // as at the end of the previous squeeze, and we could just keep it
    // around).  We don't bother, because in our application, we never
    // squeeze that much

    convert_rate_into_avx_format( rate_in_avx_format, s );

    u512 Aba, Abe, Abi, Abo, Abu;
    u512 Aga, Age, Agi, Ago, Agu;
    u512 Aka, Ake, Aki, Ako, Aku;
    u512 Ama, Ame, Ami, Amo, Amu;
    u512 Asa, Ase, Asi, Aso, Asu;

    // Copy in the state
    Aba = rate_in_avx_format[0];
    Abe = rate_in_avx_format[1];
    Abi = rate_in_avx_format[2];
    Abo = rate_in_avx_format[3];
    Abu = rate_in_avx_format[4];
    Aga = rate_in_avx_format[5];
    Age = rate_in_avx_format[6];
    Agi = rate_in_avx_format[7];
    Ago = rate_in_avx_format[8];
    Agu = rate_in_avx_format[9];
    Aka = rate_in_avx_format[10];
    Ake = rate_in_avx_format[11];
    Aki = rate_in_avx_format[12];
    Ako = rate_in_avx_format[13];
    Aku = rate_in_avx_format[14];
    Ama = rate_in_avx_format[15];
    Ame = rate_in_avx_format[16];

    // And the capacity
    Ami = cap[0];
    Amo = cap[1];
    Amu = cap[2];
    Asa = cap[3];
    Ase = cap[4];
    Asi = cap[5];
    Aso = cap[6];
    Asu = cap[7];

    for (int round = 0; round < 24; round += 2) {
        u512 Eba, Ebe, Ebi, Ebo, Ebu;
        u512 Ega, Ege, Egi, Ego, Egu;
        u512 Eka, Eke, Eki, Eko, Eku;
        u512 Ema, Eme, Emi, Emo, Emu;
        u512 Esa, Ese, Esi, Eso, Esu;

        // prepareTheta
        u512 BCa = XOR5( Aba, Aga, Aka, Ama, Asa );
        u512 BCe = XOR5( Abe, Age, Ake, Ame, Ase );
        u512 BCi = XOR5( Abi, Agi, Aki, Ami, Asi );
        u512 BCo = XOR5( Abo, Ago, Ako, Amo, Aso );
        u512 BCu = XOR5( Abu, Agu, Aku, Amu, Asu );

        // thereRhoPiChiIotaPrepareTheta(round, A, E)
        u512 Da = XOR2( BCu, ROL(BCe, 1));
        u512 De = XOR2( BCa, ROL(BCi, 1));
        u512 Di = XOR2( BCe, ROL(BCo, 1));
        u512 Do = XOR2( BCi, ROL(BCu, 1));
        u512 Du = XOR2( BCo, ROL(BCa, 1));

        Aba = XOR2( Aba, Da );
        BCa = Aba;
        Age = XOR2( Age, De );
        BCe = ROL( Age, 44 );
        Aki = XOR2( Aki, Di );
        BCi = ROL( Aki, 43 );
        Amo = XOR2( Amo, Do );
        BCo = ROL(Amo, 21);
        Asu = XOR2( Asu, Du );
        BCu = ROL(Asu, 14);
        Eba = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Eba = XOR2( Eba, _mm512_set1_epi64(KeccakF_RoundConstants[round]));
        Ebe = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Ebi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Ebo = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Ebu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );
      
        Abo = XOR2( Abo, Do );
        BCa = ROL(Abo, 28);
        Agu = XOR2( Agu, Du );
        BCe = ROL(Agu, 20);
        Aka = XOR2( Aka, Da );
        BCi = ROL(Aka, 3);
        Ame = XOR2( Ame, De );
        BCo = ROL(Ame, 45);
        Asi = XOR2( Asi, Di );
        BCu = ROL(Asi, 61);

        Ega = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Ege = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Egi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Ego = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Egu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );


        Abe = XOR2( Abe, De );
        BCa = ROL(Abe, 1);
        Agi = XOR2( Agi, Di );
        BCe = ROL(Agi, 6);
        Ako = XOR2( Ako, Do );
        BCi = ROL(Ako, 25);
        Amu = XOR2( Amu, Du );
        BCo = ROL(Amu, 8);
        Asa = XOR2( Asa, Da );
        BCu = ROL(Asa, 18);

        Eka = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Eke = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Eki = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Eko = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Eku = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Abu = XOR2( Abu, Du );
        BCa = ROL(Abu, 27);
        Aga = XOR2( Aga, Da );
        BCe = ROL(Aga, 36);
        Ake = XOR2( Ake, De );
        BCi = ROL(Ake, 10);
        Ami = XOR2( Ami, Di );
        BCo = ROL(Ami, 15);
        Aso = XOR2( Aso, Do );
        BCu = ROL(Aso, 56);

        Ema = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Eme = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Emi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Emo = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Emu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Abi = XOR2( Abi, Di );
        BCa = ROL(Abi, 62);
        Ago = XOR2( Ago, Do );
        BCe = ROL(Ago, 55);
        Aku = XOR2( Aku, Du );
        BCi = ROL(Aku, 39);
        Ama = XOR2( Ama, Da );
        BCo = ROL(Ama, 41);
        Ase = XOR2( Ase, De );
        BCu = ROL(Ase, 2);

        Esa = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Ese = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Esi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Eso = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Esu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        //    prepareTheta
        BCa = XOR5( Eba, Ega, Eka, Ema, Esa );
        BCe = XOR5( Ebe, Ege, Eke, Eme, Ese );
        BCi = XOR5( Ebi, Egi, Eki, Emi, Esi );
        BCo = XOR5( Ebo, Ego, Eko, Emo, Eso );
        BCu = XOR5( Ebu, Egu, Eku, Emu, Esu );

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = XOR2( BCu, ROL(BCe, 1) );
        De = XOR2( BCa, ROL(BCi, 1) );
        Di = XOR2( BCe, ROL(BCo, 1) );
        Do = XOR2( BCi, ROL(BCu, 1) );
        Du = XOR2( BCo, ROL(BCa, 1) );

        Eba = XOR2( Eba, Da );
        BCa = Eba;
        Ege = XOR2( Ege, De );
        BCe = ROL(Ege, 44);
        Eki = XOR2( Eki, Di );
        BCi = ROL(Eki, 43);
        Emo = XOR2( Emo, Do );
        BCo = ROL(Emo, 21);
        Esu = XOR2( Esu, Du );
        BCu = ROL(Esu, 14);

        Aba = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Aba = XOR2( Aba, _mm512_set1_epi64(KeccakF_RoundConstants[round+1]));
        Abe = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Abi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Abo = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Abu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Ebo = XOR2( Ebo, Do );
        BCa = ROL(Ebo, 28);
        Egu = XOR2( Egu, Du );
        BCe = ROL(Egu, 20);
        Eka = XOR2( Eka, Da );
        BCi = ROL(Eka, 3);
        Eme = XOR2( Eme, De );
        BCo = ROL(Eme, 45);
        Esi = XOR2( Esi, Di );
        BCu = ROL(Esi, 61);

        Aga = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Age = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Agi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Ago = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Agu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Ebe = XOR2( Ebe, De );
        BCa = ROL(Ebe, 1);
        Egi = XOR2( Egi, Di );
        BCe = ROL(Egi, 6);
        Eko = XOR2( Eko, Do );
        BCi = ROL(Eko, 25);
        Emu = XOR2( Emu, Du );
        BCo = ROL(Emu, 8);
        Esa = XOR2( Esa, Da );
        BCu = ROL(Esa, 18);

        Aka = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Ake = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Aki = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Ako = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Aku = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Ebu = XOR2( Ebu, Du );
        BCa = ROL(Ebu, 27);
        Ega = XOR2( Ega, Da );
        BCe = ROL(Ega, 36);
        Eke = XOR2( Eke, De );
        BCi = ROL(Eke, 10);
        Emi = XOR2( Emi, Di );
        BCo = ROL(Emi, 15);
        Eso = XOR2( Eso, Do );
        BCu = ROL(Eso, 56);

        Ama = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Ame = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Ami = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Amo = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Amu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );

        Ebi = XOR2( Ebi, Di );
        BCa = ROL(Ebi, 62);
        Ego = XOR2( Ego, Do );
        BCe = ROL(Ego, 55);
        Eku = XOR2( Eku, Du );
        BCi = ROL(Eku, 39);
        Ema = XOR2( Ema, Da );
        BCo = ROL(Ema, 41);
        Ese = XOR2( Ese, De );
        BCu = ROL(Ese, 2);

        Asa = _mm512_ternarylogic_epi64( BCa, BCe, BCi, AT^(~BT & CT) );
        Ase = _mm512_ternarylogic_epi64( BCe, BCi, BCo, AT^(~BT & CT) );
        Asi = _mm512_ternarylogic_epi64( BCi, BCo, BCu, AT^(~BT & CT) );
        Aso = _mm512_ternarylogic_epi64( BCo, BCu, BCa, AT^(~BT & CT) );
        Asu = _mm512_ternarylogic_epi64( BCu, BCa, BCe, AT^(~BT & CT) );
    }

    // Export the capacity
    cap[0] = Ami;
    cap[1] = Amo;
    cap[2] = Amu;
    cap[3] = Asa;
    cap[4] = Ase;
    cap[5] = Asi;
    cap[6] = Aso;
    cap[7] = Asu;

    // Export the rate
    rate_in_avx_format[0] = Aba;
    rate_in_avx_format[1] = Abe;
    rate_in_avx_format[2] = Abi;
    rate_in_avx_format[3] = Abo;
    rate_in_avx_format[4] = Abu;
    rate_in_avx_format[5] = Aga;
    rate_in_avx_format[6] = Age;
    rate_in_avx_format[7] = Agi;
    rate_in_avx_format[8] = Ago;
    rate_in_avx_format[9] = Agu;
    rate_in_avx_format[10] = Aka;
    rate_in_avx_format[11] = Ake;
    rate_in_avx_format[12] = Aki;
    rate_in_avx_format[13] = Ako;
    rate_in_avx_format[14] = Aku;
    rate_in_avx_format[15] = Ama;
    rate_in_avx_format[16] = Ame;
    convert_avx_format_into_rate( s, rate_in_avx_format );
}

} /* namespace slh_dsa */
