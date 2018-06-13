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
  RSA *rsa;
  BIGNUM *BN_three; // This may be replaced with a constant version of a BIGNUM

  BN_dec2bn(&BN_three, "3");

  for(;;) { // ugly, I know, but better than using goto IMHO
    rsa = RSA_new();
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
	 *rsap,
	 *rsaq,
	 *rsan,
	 *rsad,
	 *rsae,
	 *rsadmp1,
	 *rsadmq1,
	 *rsaiqmp;

  RSA_get0_factors(rsa, (const BIGNUM **)&rsap,
		        (const BIGNUM **)&rsaq);
  RSA_get0_key(rsa, (const BIGNUM **)&rsan,
		    (const BIGNUM **)&rsae,
	            (const BIGNUM **)&rsad);
  RSA_get0_crt_params(rsa, (const BIGNUM **)&rsadmp1,
		           (const BIGNUM **)&rsadmq1,
		           (const BIGNUM **)&rsaiqmp);

  BN_sub(p1, rsap, BN_value_one());   // p - 1
  BN_sub(q1, rsaq, BN_value_one());   // q - 1
  BN_gcd(gcd, p1, q1, ctx);           // gcd(p - 1, q - 1)
  BN_lcm(lambda, p1, q1, gcd, ctx);   // lambda(n)

  BN_gcd(chk, lambda, rsae, ctx); // check if e is coprime to lambda(n)
  if(!BN_is_one(chk))
    sane = 0;

  // check if public exponent e is less than n - 1
  BN_sub(chk, rsae, rsan); // subtract n from e to avoid checking BN_is_zero
  if(!BN_is_negative(chk))
    sane = 0;

  BN_mod_inverse(rsad, rsae, lambda, ctx);    // d
  BN_mod(rsadmp1, rsad, p1, ctx);             // d mod (p - 1)
  BN_mod(rsadmq1, rsad, q1, ctx);             // d mod (q - 1)
  BN_mod_inverse(rsaiqmp, rsaq, rsap, ctx);   // q ^ -1 mod p
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

