# This branch currently has AVX-512 support (except the SHA2-128F, SHA2-192F parameter sets)

## A multithreaded implementation of the SLH-DSA signature algorithm

This repository contains an alternative implementation of the SLH-DSA signature system (FIPS 205), as well as the reduced usage parameter sets NIST SP 800-230 (128_24, 192_24, 256_24)

## Warning: the implementation of the _24 parameter sets is not verified.  Use at your own risk

Current issues:

- There are no known-answer-tests for the _24 parameter sets (as no one has published them).  Hence, we just do 'self-consistency' tests, which is obviously very imperfect

- It does not attempt to do parallelization during key generation - that would speed things up nicely.  Currently, on my computer, key generation takes about a minute

- Even for the signing operation (which does use parallelism), it's not well balanced for the _24 parameter sets

- One obvious optimization for the _24 parameter sets is to store some of the internal merkle nodes during key generation (to speed up signature generation).  This does not do that 
