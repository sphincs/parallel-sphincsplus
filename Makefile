CC = /usr/bin/gcc
CPP = /usr/bin/g++
AR = /usr/bin/gcc-ar
CFLAGS = -Wall -Wextra -Wpedantic -O3 -g -march=native -fomit-frame-pointer -flto

%.o : %.cpp ; $(CPP) -c $(CFLAGS) $< -o $@

SOURCES =         sphincs-fast.cpp sign.cpp xn_hash.cpp \
		  verify.cpp stl.cpp \
                  sha256_hash.cpp sha256_simple.cpp sha256_robust.cpp \
		  sha256.cpp mgf1_8x.cpp sha256avx.cpp \
                  shake256_hash.cpp shake256_simple.cpp shake256_robust.cpp \
		  fips202.cpp fips202x4.cpp \
                  keccak4x/KeccakP-1600-times4-SIMD256.o \
                  haraka_hash.cpp haraka_simple.cpp haraka_robust.cpp \
		  haraka.cpp \
		  rdrand.cpp \
                  wots.cpp geo.cpp address.cpp utils.cpp
OBJECTS =         $(subst .cpp,.o,$(SOURCES))
HEADERS =         api.h internal.h mgf1_8x.h sha256avx.h xn_internal.h \
                  fips202.h fips202x4.h
TEST_SOURCES =    test_sphincs.cpp test_keygen.cpp test_sign.cpp \
		  test_verify.cpp test_thread.cpp test_testvector.cpp

TESTS = test PQCgenKAT_sign test_sphincs

.PHONY: test

default: test

all: test

tests: $(TESTS)

sphincs-fast.a: $(OBJECTS)
	ar rcs $@ $^

test: test.cpp $(OBJECTS)
	$(CPP) $(CFLAGS) -o $@ $< $(OBJECTS) -lpthread

test_sphincs: $(TEST_SOURCES) $(OBJECTS)
	$(CPP) $(CFLAGS) -o $@ $(TEST_SOURCES) $(OBJECTS) -lpthread

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
