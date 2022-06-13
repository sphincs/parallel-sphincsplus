/*
 * This is the test harness for the fast Sphincs+ implementation
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "test_sphincs.h"

/*
 * This is the list of tests we know about
 */
static struct {
    const char *keyword;               /* The name of this test */
    bool (*test_routine)(bool, enum noise_level);  /* How to run this test */
    const char *test_name;             /* Extended description */
    bool warn_expense;                 /* Should we warn that this test */
                                       /* will take a while in -full mode */
    bool (*test_enabled)(bool);        /* Check if this tests is enabled */
} test_list[] = {
    { "sha512", test_sha512, "internal SHA-512 implementation test", false, 0 },
    { "testvector", test_testvector, "test vectors extracted from the reference code", false, 0 },
    { "keygen", test_keygen, "key generation test", false, 0 },
    { "sign", test_sign, "signature generation test", false, 0 },
    { "verify", test_verify, "signature verification test", true, 0 },
    { "thread", test_thread, "threading test", false, 0 },
    { "fault", test_fault, "fault detection test", false, 0 },
 /* Add more here */  
};

/*
 * This will run the listed tests; tests is a bitmap containing which tests
 * should be run; tests&1 is test_lis[t0], tests&2 is test_list[1], etc
 */
static int run_tests( unsigned tests, bool force_tests, bool fast_flag,
                      enum noise_level level ) {
    int success_flag = EXIT_SUCCESS;
    unsigned i;
    for (i = 0; i < sizeof test_list / sizeof *test_list; i++) {
        if (0 == ( tests & (1<<i))) continue;
        printf( "Running %s", test_list[i].test_name );
        if (test_list[i].warn_expense && !fast_flag) {
            printf( " (warning: this will take a while)" );
        }
        printf( ":\n" );
        fflush(stdout);
        if (test_list[i].test_enabled &&
                                   !test_list[i].test_enabled(fast_flag)) {
            continue;
        }
        bool test_passed = test_list[i].test_routine(fast_flag, level);
        if (test_passed) {
            printf( "  Passed        \n" );
        } else {
            printf( "  **** TEST FAILED ****\n" );
            success_flag = EXIT_FAILURE;
            if (!force_tests) break;   /* Stop on first failure? */
        }
    }
    return success_flag;
}

static void usage(char *program_name) {
    printf( "Usage: %s [-f] [-q] [-v] [-full] [tests]\n", program_name );
    printf( "   \"all\" will run all tests\n" );
    printf( "   -q will remove progress messages during the longer tests\n" );
    printf( "   -v will add additional progress messages during some tests\n" );
    printf( "   -f will force running of all tests, even on failure\n" );
    printf( "   -full will have the tests run the entire suite\n" );
    printf( "          Warning: some tests may take over an hour in full mode\n" );
    printf( "Supported tests:\n" );
    unsigned i;
    for (i = 0; i < sizeof test_list / sizeof *test_list; i++) {
        printf( "    \"%s\": %s\n", test_list[i].keyword, test_list[i].test_name );
    }
}

int main( int argc, char **argv ) {
    int i;
    unsigned tests_to_run = 0;
    bool force_tests = false;
    bool fast_flag = true;
    enum noise_level level = whisper;
    for (i = 1; i < argc; i++) {
        char *test = argv[i];
        bool found_test = false;
        unsigned j;
        for (j = 0; j < sizeof test_list / sizeof *test_list; j++) {
            if (0 == strcmp( test, test_list[j].keyword)) {
                tests_to_run |= (1<<j);
                found_test = true;
                break;
            }
        }
        if (found_test) continue;

        /* Not any of the standard tests; check to see if it's an adverb */ 
        if (0 == strcmp( test, "all" )) {
            tests_to_run = ~0;    /* All of them */
        } else if (0 == strcmp( test, "-f" )) {
            force_tests = true;
        } else if (0 == strcmp( test, "-full" )) {
            fast_flag = false;
        } else if (0 == strcmp( test, "-q" )) {
            level = quiet;
        } else if (0 == strcmp( test, "-v" )) {
            level = loud;
        } else {
            printf( "Unrecognized test %s\n", test );
            usage( argv[0] );
            return EXIT_FAILURE;
        }
    }
    if (tests_to_run == 0) {
        usage( argv[0] );
        exit(EXIT_FAILURE);  /* FAILURE == We didn't pass the tests */
    }

    return run_tests( tests_to_run, force_tests, fast_flag, level );
}
