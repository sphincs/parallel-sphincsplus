#CC = /usr/bin/gcc
#CPP = /usr/bin/g++
#AR = /usr/bin/gcc-ar

#uncomment these if this is standard or your make command is struggling to make the connection to your gcc system

CFLAGS = -Wall -Wextra -Wpedantic -O3 -g -march=native -fomit-frame-pointer -flto

INCLUDES = -I$(CURDIR)/ -I$(CURDIR)/include/ -I$(CURDIR)/keccak4x/

sphincsIncludeDir = $(CURDIR)/include/
sphincsSrcDir = $(CURDIR)/src/
keccakDir = $(CURDIR)/keccak4x/
nistDir = $(CURDIR)/nist/

objDir = $(CURDIR)/obj/
INSTALLDIR = $(CURDIR)/lib/

SOURCES = $(sphincsSrcDir)sphincs-fast.cpp $(sphincsSrcDir)sign.cpp $(sphincsSrcDir)xn_hash.cpp \
		  $(sphincsSrcDir)verify.cpp $(sphincsSrcDir)stl.cpp \
          $(sphincsSrcDir)sha256_hash.cpp $(sphincsSrcDir)sha256_simple.cpp $(sphincsSrcDir)sha256_robust.cpp \
		  $(sphincsSrcDir)sha256.cpp $(sphincsSrcDir)mgf1_8x.cpp $(sphincsSrcDir)sha256avx.cpp \
          $(sphincsSrcDir)shake256_hash.cpp $(sphincsSrcDir)shake256_simple.cpp $(sphincsSrcDir)shake256_robust.cpp \
		  $(sphincsSrcDir)fips202.cpp $(sphincsSrcDir)fips202x4.cpp \
          keccak4x/KeccakP-1600-times4-SIMD256.cpp \
          $(sphincsSrcDir)haraka_hash.cpp $(sphincsSrcDir)haraka_simple.cpp $(sphincsSrcDir)haraka_robust.cpp \
		  $(sphincsSrcDir)haraka.cpp \
		  $(sphincsSrcDir)rdrand.cpp \
          $(sphincsSrcDir)wots.cpp $(sphincsSrcDir)geo.cpp $(sphincsSrcDir)address.cpp $(sphincsSrcDir)utils.cpp

OBJECTS =  $(subst .cpp,.o,$(SOURCES))

HEADERS =  $(sphincsIncludeDir)api.h $(sphincsIncludeDir)internal.h $(sphincsIncludeDir)mgf1_8x.h $(sphincsIncludeDir)sha256avx.h $(sphincsIncludeDir)xn_internal.h \
                  $(sphincsIncludeDir)fips202.h $(sphincsIncludeDir)fips202x4.h

TEST_SOURCES =    $(sphincsSrcDir)test_sphincs.cpp $(sphincsSrcDir)test_keygen.cpp $(sphincsSrcDir)test_sign.cpp \
		  $(sphincsSrcDir)test_verify.cpp $(sphincsSrcDir)test_thread.cpp $(sphincsSrcDir)test_testvector.cpp

TESTS = test PQCgenKAT_sign test_sphincs

default : $(OBJECTS)

keccak4x/KeccakP-1600-times4-SIMD256.o: keccak4x/align.h keccak4x/brg_endian.h \
					keccak4x/KeccakP-1600-times4-SnP.h \
					keccak4x/KeccakP-1600-unrolling.macros \
					keccak4x/SIMD256-config.h
	$(CXX) $(CFLAGS) $(INCLUDES) -c keccak4x/KeccakP-1600-times4-SIMD256.cpp -o $@
	
.PHONY: test

all: test

tests: $(TESTS)

.PHONY : install

.PHONY : lib

lib : install

$(OBJECTS): %.o : %.cpp
	$(CXX) -c $(CFLAGS) $(INCLUDES) $< -o $@

libSphincs.a: $(OBJECTS)
	mkdir -p $(INSTALLDIR)
	ar rcs $@ $^
	cp -p libSphincs.a $(INSTALLDIR)
	rm libSphincs.a
	
install : libSphincs.a

test: $(sphincsSrcDir)test.cpp $(OBJECTS)
	$(CXX) $(CFLAGS) $(INCLUDES) -L$(INSTALLDIR) -o $@ $< -lpthread -lSphincs

test_sphincs: $(TEST_SOURCES) $(OBJECTS)
	$(CXX) $(CFLAGS) $(INCLUDES) -L$(INSTALLDIR) -o $@ $(TEST_SOURCES) -lpthread -lSphincs

PQCgenKAT_sign: PQCgenKAT_sign.o nist/nist_api.cpp rng.o $(OBJECTS) $(DET_HEADERS)
	        $(CXX) $(CFLAGS) $(INCLUDES) -L$(INSTALLDIR)  -o $@ nist/nist_api.cpp rng.o $< -lcrypto -lpthread -lSphincs

speed_test: $(sphincsSrcDir)speed_test.cpp $(OBJECTS)
	$(CXX) $(CFLAGS) $(INCLUDES) -L$(INSTALLDIR) -o $@ $< -lpthread -lSphincs

PQCgenKAT_sign.o: nist/PQCgenKAT_sign.c
	$(CC) $(CFLAGS) $(INCLUDES) -c nist/PQCgenKAT_sign.c -o $@

randombytes.o: nist/randombytes.c
	$(CC) $(CFLAGS) $(INCLUDES) -c nist/randombytes.c -o $@

rng.o: nist/rng.c
	$(CC) $(CFLAGS) $(INCLUDES) -c nist/rng.c -o $@

.PHONY : cleanall
.PHONY : cleanlib

cleanall : clean

clean:
	-$(RM) -rf $(TESTS) *.a *.o $(objDir) $(INSTALLDIR) $(sphincsSrcDir)/*.o $(keccakDir)/*.o $(nistDir)/*.o
	
cleanlib : 
	-$(RM) -rf *.a $(INSTALLDIR)
