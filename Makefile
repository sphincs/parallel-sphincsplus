CC = /usr/bin/gcc
CPP = /usr/bin/g++
AR = /usr/bin/gcc-ar
CFLAGS = -Wall -Wextra -Wpedantic -O3 -g -march=native -fomit-frame-pointer -flto

%.o : %.cpp ; $(CPP) -c $(CFLAGS) $< -o $@

SOURCES =         slh-dsa-fast.cpp sign.cpp xn_hash.cpp \
		  verify.cpp stl.cpp prehash.cpp \
                  sha256_hash.cpp sha256_simple.cpp \
		  sha256.cpp sha256avx.cpp \
		  sha512_hash.cpp sha512.cpp mgf1_512_4x.cpp sha512avx.cpp \
		  sha512_simple.cpp \
                  shake256_hash.cpp shake256_simple.cpp \
		  fips202.cpp fips202x4.cpp \
                  keccak4x/KeccakP-1600-times4-SIMD256.o \
		  rdrand.cpp \
                  wots.cpp geo.cpp address.cpp utils.cpp
OBJECTS =         $(subst .cpp,.o,$(SOURCES))
HEADERS =         api.h internal.h sha256avx.h xn_internal.h \
                  fips202.h fips202x4.h
TEST_SOURCES =    test_sphincs.cpp test_keygen.cpp test_sign.cpp \
		  test_verify.cpp test_thread.cpp test_testvector_sign.cpp \
		  test_testvector_keygen.cpp \
		  test_sha512.cpp test_context.cpp

TESTS = test test_slh_dsa

.PHONY: test

default: test

all: test

tests: $(TESTS)

slh-dsa-fast.a: $(OBJECTS)
	ar rcs $@ $^

test: test.cpp $(OBJECTS)
	$(CPP) $(CFLAGS) -o $@ $< $(OBJECTS) -lpthread

test_slh_dsa: $(TEST_SOURCES) $(OBJECTS)
	$(CPP) $(CFLAGS) -o $@ $(TEST_SOURCES) $(OBJECTS) -lpthread

# The github action expects 'test_sphincs'
test_sphincs: test_slh_dsa
	cp test_slh_dsa test_sphincs

PQCgenKAT_sign: PQCgenKAT_sign.o nist/nist_api.cpp rng.o $(OBJECTS) $(DET_HEADERS)
	        $(CPP) $(CFLAGS) -o $@ $(OBJECTS) nist/nist_api.cpp rng.o $< -lcrypto -lpthread

speed_test: speed_test.cpp $(OBJECTS)
	$(CPP) $(CFLAGS) -o $@ $(OBJECTS) $< -lpthread

keccak4x/KeccakP-1600-times4-SIMD256.o: keccak4x/align.h keccak4x/brg_endian.h \
					keccak4x/KeccakP-1600-times4-SIMD256.cpp \
					keccak4x/KeccakP-1600-times4-SnP.h \
					keccak4x/KeccakP-1600-unrolling.macros \
					keccak4x/SIMD256-config.h
	$(CPP) $(CFLAGS) -c keccak4x/KeccakP-1600-times4-SIMD256.c -o $@

PQCgenKAT_sign.o: nist/PQCgenKAT_sign.c
	$(CC) $(CFLAGS) -c nist/PQCgenKAT_sign.c -o $@

randombytes.o: nist/randombytes.c
	$(CC) $(CFLAGS) -c nist/randombytes.c -o $@

rng.o: nist/rng.c
	$(CC) $(CFLAGS) -c nist/rng.c -o $@


clean:
	-$(RM) $(TESTS)
