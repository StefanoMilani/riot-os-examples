/**
 * @file        utils.c
 * @brief       Performance Evaluation of Signign Algorithm
 *
 * @author      Stefano Milani <milani@diag.uniroma1.it>
 *
 */

#include "utils.h"

void print_key(uint8_t* key, int size) {
	for(int i = 0; i < size; i++) {
		if(i%5==0) 
			printf("\n");
		printf("0x%x\t",key[i]);
	}
}

int hash_msg(uint8_t *msg, size_t msg_size, uint8_t *digest) {
  sha256(msg, msg_size, digest);
  if(digest == NULL)
    return 0;
  return 1;
}

int rng_function(uint8_t *dest, unsigned size) {
  random_bytes(dest, size);
  return 1;
}

int make_ecc_keys(uint8_t *public_key, uint8_t *private_key, uECC_Curve *curve) {
  uECC_set_rng(&rng_function);
  return uECC_make_key(public_key, private_key, *curve);
}

uint32_t ecc_sign(uint8_t *msg, size_t msg_size, const uint8_t *private_key, uECC_Curve *curve, unsigned testrounds) {
  uint32_t time_start, time_end;
  uint32_t delta_sum = 0;
  int res;
  unsigned i;

  uint8_t digest[SHA256_DIGEST_LENGTH];
  res = hash_msg(msg, msg_size, (void *) digest);
  ERROR_HANDLER(res, "Failed to compute hash");

  size_t signature_len = 2 * uECC_curve_private_key_size(*curve);
  uint8_t signature[signature_len];
  for(i = 0; i < testrounds; i++) {
    time_start = xtimer_now_usec();
    res = uECC_sign(private_key, (const uint8_t *) digest, SHA256_DIGEST_LENGTH, signature, *curve);
    time_end = xtimer_now_usec();
    ERROR_HANDLER(res, "Failed to compute ECC signature");
    delta_sum +=  (time_end - time_start);
  }

  return delta_sum / testrounds;
}

uint32_t aes_cmac(const uint8_t *msg, size_t msg_size, uint8_t *key, unsigned testrounds) {
  uint32_t time_start, time_end;
  uint32_t delta_sum = 0;
  int res;
  unsigned i;
  aes128_cmac_context_t context;

  res = aes128_cmac_init(&context, key, AES128_CMAC_BLOCK_SIZE);
  if(res != CIPHER_INIT_SUCCESS) {
    fprintf(stderr, "Failed to initialize aes cmac context. ERR: %d", res);
    exit(1);
  }
  aes128_cmac_update(&context, (void*) msg, msg_size);

  uint8_t digest[AES128_CMAC_BLOCK_SIZE];
  for(i = 0; i < testrounds; i++) {
    time_start = xtimer_now_usec();
    aes128_cmac_final(&context, (void*) digest);
    time_end = xtimer_now_usec();
    delta_sum +=  (time_end - time_start);
  }

  return delta_sum / testrounds;
}
