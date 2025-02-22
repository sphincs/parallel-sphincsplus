## A multithreaded implementation of the SLH-DSA signature algorithm

This repository contains an alternative implementation of the SLH-DSA signature system (FIPS 205)

The specific features that this implements (that the reference code doesn't):

- It is multithreaded; that is, it can split the job of producing a signature over several threads

- It can support multiple parameter sets at once

It does assume that you have the AVX2 and AES_NI instructions available, as well as the Posix multithreading API - if not, well, I'll refer you to the reference code...
