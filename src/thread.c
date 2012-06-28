// thread procs for shallot

#include "config.h"

#include <stdint.h> // OpenBSD needs this included before sys/endian.h

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)
  #include "linux.h"
#else
  #include <sys/param.h> // OpenBSD needs this early on too
  #include <sys/endian.h>
#endif

#include "math.h"
#include "print.h"
#include "error.h"
#include "thread.h"
#include "defines.h"
#include "globals.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

void *worker(void *params) { // life cycle of a cracking pthread
  uint64_t e_be; // storage for our "big-endian" version of e
  uint8_t buf[SHA1_DIGEST_LEN],
          der[RSA_EXP_DER_LEN + 1], // TODO: is the size of this right?
          optimum = *(uint8_t*)params;
  char onion[BASE32_ONIONLEN];
  SHA_CTX hash, copy;
  RSA *rsa;

  while(!found) {
    // keys are only generated every so often
    // every 549,755,781,120 tries by default

    if(optimum)
      rsa = easygen(RSA_OPTM_BITLEN - RSA_PK_E_LENGTH * 8, RSA_PK_E_LENGTH,
                    der, RSA_OPT_DER_LEN, &hash);
    else
      rsa = easygen(RSA_KEYS_BITLEN, RSA_PK_E_LENGTH, der, RSA_EXP_DER_LEN,
                    &hash);

    if(!rsa) // if key generation fails (no [P]RNG seed?)
      error(X_KEY_GEN_FAILS);

    uint8_t e_bytes = RSA_PK_E_LENGTH; // number of bytes e occupies
    uint64_t e = RSA_PK_EXPONENT;      // public exponent
    uint64_t e_byte_thresh;

    int_pow(2, e_bytes * 8, &e_byte_thresh);
    e_byte_thresh++;

    uint8_t *e_ptr = ((uint8_t*)&e_be) + 8 - e_bytes;

    while((e <= elim) && !found) { // main loop
      // copy the relevant parts of our already set up context
      memcpy(&copy, &hash, SHA_REL_CTX_LEN); // 40 bytes here...
      copy.num = hash.num;                   // and don't forget the num (9)

      // convert e to big-endian format
      e_be = htobe64(e);

      // compute SHA1 digest (majority of loop time spent here!)
      SHA1_Update(&copy, e_ptr, e_bytes);
      SHA1_Final(buf, &copy);

      base32_onion(onion, buf); // base32-encode SHA1 digest
      loop++;                   // keep track of our tries...

      if(!regexec(regex, onion, 0, 0, 0)) { // check for a match

        // let our main thread know on which thread to wait
        lucky_thread = pthread_self();
        found = 1; // kill off our other threads, asynchronously

        if(monitor)
          printf("\n"); // keep our printing pretty!

        if(!BN_bin2bn(e_ptr, e_bytes, rsa->e)) // store our e in the actual key
          error(X_BIGNUM_FAILED);              // and make sure it got there

        if(!sane_key(rsa))        // check our key
          error(X_YOURE_UNLUCKY); // bad key :(

        print_onion(onion); // print our domain
        print_prkey(rsa);   // and more importantly the key

        RSA_free(rsa); // free up what's left

        return 0;
      }

      e += 2; // do *** NOT *** forget this!

      if(e == e_byte_thresh) { // ASN.1 stuff (hey, it could be worse!)
        // calculate our new threshold
        int_pow(2, ++e_bytes * 8, &e_byte_thresh);
        e_byte_thresh++;

        if(optimum) {
          RSA_free(rsa);
          easygen(RSA_OPTM_BITLEN - e_bytes * 8, e_bytes, der, RSA_OPT_DER_LEN,
                  &hash);

          if(!rsa)
            error(X_KEY_GEN_FAILS);
        } else {
          // play with our key structure (do not try this at home!)
          der[RSA_ADD_DER_OFF]++;
          der[RSA_EXP_DER_LEN - RSA_PK_E_LENGTH - 1]++;

          // and our prebuilt hash
          SHA1_Init(&hash); // TODO: move to a function
          SHA1_Update(&hash, der, RSA_EXP_DER_LEN - RSA_PK_E_LENGTH);
        }

        e_ptr--; // and move the pointer back
      }
    }
    RSA_free(rsa);
  }

  return 0;
}

void *monitor_proc(void *unused) {
  fprintf(stderr,"\033[sPlease wait a moment for statistics...");
  time_t start = time(NULL);

  for(;;) {
    fflush(stderr); // make sure it gets printed
    int i = 0;

    //this next little section sleeps 20 seconds before continuing
    //and checks every second whether the maximum execution time (-x) has
    //been reached.
    for(i=0;i<20;i++){
      sleep(1);
      time_t current = time(NULL);
      time_t elapsed = current - start;
      if(elapsed>maxexectime || elapsed==maxexectime){
        if(maxexectime > 0){
          error(X_MAXTIME_REACH);
        }
      }
    }


    if(found)
      return 0;

    time_t current = time(NULL);
    time_t elapsed = current - start;

    if(!elapsed)
      continue; // be paranoid and avoid divide-by-zero exceptions

    fprintf(stderr,"\033[u\033[KHashes: %-20"PRIu64"  Time: %-10d  Speed: %-"PRIu64"",
           loop, (int)elapsed, loop / elapsed);

  }

  return 0; // unreachable code, but prevents warnings (!?)
}
