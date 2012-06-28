#ifndef DEFINES_H
#define DEFINES_H

#include "config.h"
#include <inttypes.h>

// our ever-important version string
#define VERSION "0.0.3-alpha"

// default values
#define DEFAULT_THREADS 1 // not used on anything but unknown systems
#define DEFAULT_E_LIMIT 0xFFFFFFFFFFull // must be odd and <= MAXIMUM_E_LIMIT 
                                        // and >= RSA_PK_EXPONENT
#define MAXIMUM_E_LIMIT 0xFFFFFFFFFFFFFFFDull

// crypt constants
#define REGEX_COMP_LMAX 0x40
#define SHA1_DIGEST_LEN 20
#define RSA_KEYS_BITLEN 0x400
#define RSA_OPTM_BITLEN 0x380 // remember to subtract the length of e (in bits)
// be sure to keep these constants in sync if you change them!
#define RSA_PK_EXPONENT 0x10001ull
#define RSA_PK_E_LENGTH 3
#define RSA_EXP_DER_LEN 0x8C
#define RSA_OPT_DER_LEN 0x77
#define RSA_ADD_DER_OFF 2 // don't ask...
#define SHA_REL_CTX_LEN 10 * sizeof(SHA_LONG)

#define BASE32_ONIONLEN 16
#define BASE32_ALPHABET "abcdefghijklmnopqrstuvwxyz234567"

#define PRINT_ONION_STR "Found matching domain after %"PRIi64" tries: %s.onion"
#define PRINT_ONION_MAX 79

#ifdef LINUX_PORT
  // Linux constants (lol no API)
  #define CPUINFO_BUF_SIZE 0x400
  #define CPUINFO_PATH "/proc/cpuinfo"
  #define CPUINFO_PROC_STR "processor"
  #define CPUINFO_PROC_STR_LEN 9 // don't include trailing NULL
  // sanity checking for constants
  #if CPUINFO_BUF_SIZE < 0x100
    #error CPUINFO_BUFFER_SIZE set too small.  Please make it bigger.
  #elif CPUINFO_BUF_SIZE > 0x7FFF
    #error CPUINFO_BUFFER_SIZE set too large.  Please make it smaller.
  #endif
#endif

#endif

