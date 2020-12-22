// custom math routines for shallot

#include "math.h"
#include "defines.h"

void int_pow(uint32_t base, uint8_t pwr, uint64_t *out) { // integer pow()
  *out = (uint64_t)base;
  uint8_t round = 1;
  for(; round < pwr; round++)
    *out *= base;
}

// LCM for BIGNUMs
uint8_t BN_lcm(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *gcd, BN_CTX *ctx) {
  BIGNUM *tmp = BN_CTX_get(ctx);
  if(!BN_div(tmp, NULL, a, gcd, ctx))
    return 0;
  if(!BN_mul(r, b, tmp, ctx))
    return 0;
  return 1;
}

// wraps RSA key generation, DER encoding, and initial SHA-1 hashing
RSA *easygen(uint16_t num, uint8_t len, uint8_t *der, uint8_t edl,
             SHA_CTX *ctx) {
  uint8_t der_len;
  RSA *rsa = RSA_new();
  BIGNUM *BN_three;
  BN_dec2bn(&BN_three, "3");

  for(;;) { // ugly, I know, but better than using goto IMHO
    RSA_generate_key_ex(rsa, num, BN_three, NULL);

    if(!rsa) // if key generation fails (no [P]RNG seed?)
      return rsa;

    // encode RSA key in X.690 DER format
    uint8_t *tmp = der;
    der_len = i2d_RSAPublicKey(rsa, &tmp);

    if(der_len == edl - len + 1)
      break; // encoded key was the correct size, keep going

    RSA_free(rsa); // encoded key was the wrong size, try again
  }

  // adjust for the actual size of e
  der[RSA_ADD_DER_OFF] += len - 1;
  der[der_len - 2]     += len - 1;

  // and prepare our hash context
  SHA1_Init(ctx);
  SHA1_Update(ctx, der, der_len - 1);

  return rsa;
}

uint8_t sane_key(RSA *rsa) { // checks sanity of a RSA key (PKCS#1 v2.1)
  uint8_t sane = 1;

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *p1     = BN_CTX_get(ctx), // p - 1
         *q1     = BN_CTX_get(ctx), // q - 1
         *chk    = BN_CTX_get(ctx), // storage to run checks with
         *gcd    = BN_CTX_get(ctx), // GCD(p - 1, q - 1)
         *lambda = BN_CTX_get(ctx), // LCM(p - 1, q - 1)
         *p, *q, *n, *e, *d, *dmp1, *dmq1, *iqmp;
  RSA_get0_factors(rsa, (const BIGNUM **)&p, (const BIGNUM **)&q);
  BN_sub(p1, p, BN_value_one()); // p - 1
  BN_sub(q1, q, BN_value_one()); // q - 1
  BN_gcd(gcd, p1, q1, ctx);           // gcd(p - 1, q - 1)
  BN_lcm(lambda, p1, q1, gcd, ctx);   // lambda(n)

  RSA_get0_key(rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, (const BIGNUM **)&d);
  BN_gcd(chk, lambda, e, ctx); // check if e is coprime to lambda(n)
  if(!BN_is_one(chk))
    sane = 0;

  // check if public exponent e is less than n - 1
  BN_sub(chk, e, n); // subtract n from e to avoid checking BN_is_zero
  if(!BN_is_negative(chk))
    sane = 0;

  RSA_get0_crt_params(rsa, (const BIGNUM **)&dmp1, (const BIGNUM **)&dmq1, (const BIGNUM **)&iqmp);
  BN_mod_inverse(d, e, lambda, ctx);    // d
  BN_mod(dmp1, d, p1, ctx);             // d mod (p - 1)
  BN_mod(dmq1, d, q1, ctx);             // d mod (q - 1)
  BN_mod_inverse(iqmp, q, p, ctx); // q ^ -1 mod p
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  // this is excessive but you're better off safe than (very) sorry
  // in theory this should never be true unless I made a mistake ;)
  if((RSA_check_key(rsa) != 1) && sane) {
    fprintf(stderr, "WARNING: Key looked okay, but OpenSSL says otherwise!\n");
    sane = 0;
  }

  return sane;
}

