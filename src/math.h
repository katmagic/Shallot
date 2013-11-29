#ifndef MATH_H
#define MATH_H

#include "config.h"

// check config - include in first file including config
#ifdef BSD
  #ifdef LINUX_PORT
    #error BSD and LINUX_PORT defined.
  #endif
  #ifdef GENERIC
    #error BSD and GENERIC defined.
  #endif
#elif defined(LINUX_PORT)
  #ifdef GENERIC
    #error LINUX_PORT and GENERIC defined.
  #endif
#elif !defined(GENERIC)
  #error Nothing defined.  Please run ./configure
#endif

#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

uint8_t BN_lcm(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *gcd, BN_CTX *ctx);
RSA *easygen(uint16_t num, uint8_t len, uint8_t *der, uint8_t edl,
             SHA_CTX *ctx);
uint8_t sane_key(RSA *rsa);

#endif

