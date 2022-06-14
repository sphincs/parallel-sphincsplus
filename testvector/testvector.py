#! /usr/bin/env python3
import fileinput
import itertools
import os
import sys
from subprocess import DEVNULL, run

implementations = [
                   ('ref', ['shake', 'sha2', 'haraka']),
                   ]

options = ["f", "s"]
sizes = [128, 192, 256]
thashes = ['robust', 'simple']

if os.path.exists("testvector.h"):
    os.remove("testvector.h")
file1 = open("testvector.h", "a" );
file1.write( "/* This is a computer generated file */\n" );
file1.write( "/* Do not edit this directly */\n" );
file1.close()

for impl, fns in implementations:
    params = os.path.join(impl, "params.h")
    for fn in fns:
        for opt, size, thash in itertools.product(options, sizes, thashes):
            paramset = "sphincs-{}-{}{}".format(fn, size, opt)
            paramfile = "params-{}.h".format(paramset)
            print("Generating testvectors ", paramset, thash, "using", impl, flush=True)
            print("Testing ", fn, size, opt, thash)
            file1 = open("testvector.h", "a" );
            file1.write( "{\n    \"" );
            file1.write( fn );
            file1.write( "_" );
            file1.write( str(size) );
            file1.write( opt );
            file1.write( "_" );
            file1.write( thash );
            file1.write( "\",\n" );
            file1.close()
            params = 'PARAMS={}'.format(paramset)  # overrides Makefile var
            thash = 'THASH={}'.format(thash)  # overrides Makefile var
            run(["make", "-C", impl, "clean", thash, params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "testvectors", thash, params],
                stdout=DEVNULL, stderr=sys.stderr)
            run(["make", "-C", impl, "testvector", thash, params],
                stdout=sys.stdout, stderr=sys.stderr)
            print(flush=True)
            file1 = open("testvector.h", "a" );
            file1.write( "},\n" );
            file1.close()

        print(flush=True)

