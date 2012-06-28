// error handling for shallot

#include "error.h"
#include "globals.h"
#include "defines.h"

#include <stdio.h>
#include <stdlib.h>

// help - how to use this stuff
void usage(void) {
  printf("Usage: shallot [-dmopv] [-f <file>] [-t count] [-x time] [-e limit] pattern\n"
         "  -d        : Daemonize (requires -f)\n"
         "  -m        : Monitor mode (incompatible with -f)\n"
	 "  -o        : Optimize RSA key size to improve SHA-1 hashing speed\n"
         "  -p        : Print 'pattern' help and exit\n"
         "  -f <file> : Write output to <file>\n"
         "  -t count  : Forces exactly count threads to be spawned\n"
         "  -x secs   : Sets a limit on the maximum execution time. Has no effect without -m\n"
         "  -e limit  : Manually define the limit for e\n"
         "Version: %s\n", VERSION);
  exit(X_WRONG_NUMARGS);
}

void pattern(void) {
  printf("base32 alphabet allows letters [a-z] and digits [2-7]\n"
         "pattern can be a POSIX-style regular expression, e.g.\n"
         "  xxx           must contain 'xxx'\n"
         "  bar$          must end with 'bar'\n"
         "  ^foo          must begin with 'foo'\n"
         "  b[a4]r        may contain leetspeech ;)\n"
         "  ^ab|^cd       must begin with 'ab' or 'cd'\n"
         "  [a-z]{16}     must contain letters only, no digits\n"
         "  ^dusk.*dawn$  must begin with 'dusk' and end with 'dawn'\n");
  exit(X_WRONG_NUMARGS);
}

// our big error handling/reporting function
void error(int32_t code) {
  switch(code) {
    case X_REGEX_COMPILE: {
      fprintf(stderr, "ERROR: Bad pattern.  Try again with something else!\n");
      break;
    }

    case X_REGEX_INVALID: {
      fprintf(stderr, "ERROR: Pattern cannot contain '-'.\n");
      break;
    }

    case X_SGNL_INT_TERM: {
      fprintf(stderr, "\nCaught SIGINT/SIGTERM after %"PRIu64" tries - exiting.\n",
              loop);
      break;
    }

    case X_YOURE_UNLUCKY: {
      fprintf(stderr, "\nERROR: You happened to find a bad key - congrats.\n");
      break;
    }

    case X_KEY_GEN_FAILS: {
      fprintf(stderr, "ERROR: RSA Key Generation failed.  This is bad.\n");
      break;
    }

    case X_THREAD_CREATE: {
      fprintf(stderr, "ERROR: Failed to create thread.  Terminating...\n");
      break;
    }

    case X_BIGNUM_FAILED: {
      fprintf(stderr, "ERROR: Failed to covert uint64_t to BIGNUM.\n");
      break;
    }

    case X_INVALID_THRDS: {
      fprintf(stderr, "ERROR: Invalid number of threads\n");
      break;
    }

    case X_EXCLUSIVE_OPT: {
      fprintf(stderr, "ERROR: -m is incompatible with -f/-v\n");
      break;
    }

    case X_INVALID_E_LIM: {
      fprintf(stderr, "ERROR: e limit must be odd, >= %llu, and <= %llu\n",
              RSA_PK_EXPONENT, MAXIMUM_E_LIMIT);
      break;
    }

    case X_NEED_FILE_OUT: {
      fprintf(stderr, "ERROR: -d requires -f <file>\n");
      break;
    }

    case X_FILE_OPEN_ERR: {
      fprintf(stderr, "ERROR: Couldn't open file for output\n");
      break;
    }

    case X_DAEMON_FAILED: {
      fprintf(stderr, "ERROR: Daemonization failed\n");
      break;
    }

    case X_OUT_OF_MEMORY: {
			fprintf(stderr, "ERROR: Out of memory error.\n");
			break;
		}
    case X_MAXTIME_REACH: {
                        fprintf(stderr,"\n%s\n","Maximum execution time reached; exiting...");
                        break;
                }


#ifdef BSD
    case X_SYSCTL_FAILED: {
      fprintf(stderr, "ERROR: sysctlbyname failed.\n");
      break;
    }

#elif defined(LINUX_PORT)
    case X_BAD_FILE_DESC: {
      fprintf(stderr, "ERROR: Couldn't open processor information.\n");
      break;
    }

    case X_ABNORMAL_READ: {
      fprintf(stderr, "ERROR: Failed reading processor information.\n");
      break;
    }
#endif

    default: {
      fprintf(stderr, "Generic error.  You should never see this...\n");
      break;
    }
  } // end switch

  exit(code);
}

