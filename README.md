# This branch currently has AVX-512 support (except the SHA2-128F, SHA2-192F parameter sets)

## A multithreaded implementation of the SLH-DSA signature algorithm

This repository contains an alternative implementation of the SLH-DSA signature system (FIPS 205)

The specific features that this implements (that the reference code doesn't):

- It is multithreaded; that is, it can split the job of producing a signature over several threads

- It can support multiple parameter sets at once

It does assume that you have the AVX2 instructions available, as well as the Posix multithreading API - if not, well, I'll refer you to the reference code...

If you're looking for an implementation of the Sphincs+ round 3 code, check out the consistent-basew branch

Interesting branches:
- fault  - Attempts to protect against fault attacks (by performing the critical computations twice and comparing)
- sfluhrer-avx-512 - Uses the AVX-512 instruction set to accelerate things (if available, if not, it falls back to AVX-2)
- dwarf   - Adds support for the proposed rls128cs1, rls192cs1, rls256cs1 parameter sets (both SHA2 and SHAKE)
