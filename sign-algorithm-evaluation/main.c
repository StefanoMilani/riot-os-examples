/**
 * @file        main.c
 * @brief       Performance Evaluation of Signign Algorithm
 *
 * @author      Stefano Milani <milani@diag.uniroma1.it>
 *
 */

#include "utils.h"

#define TESTROUNDS 512
#define TEST_MESSAGE "Not so long test message."
#define TEST_MESSAGE_LEN strlen(TEST_MESSAGE)

int main(void) {
  int res;
  uint32_t ecc_elapsed_time, aes_elapsed_time;

  uECC_Curve curve = uECC_secp256r1();

  // Keys Sizes and Initialization
  int private_key_size = uECC_curve_private_key_size(curve);
  int public_key_size = uECC_curve_public_key_size(curve);
  uint8_t private_key[private_key_size];
  uint8_t public_key[public_key_size];
  res = make_ecc_keys(public_key, private_key, &curve);
  ERROR_HANDLER(res, "Failed to create key pair!");

  uint8_t aes_key[AES128_CMAC_BLOCK_SIZE];
  random_bytes(aes_key, AES128_CMAC_BLOCK_SIZE);

  // TEST ECC SIGN ALGORITHM ELAPSED TIME
  printf("\n====== ECC SIGN ALGORITHM TEST START =====\n");
  printf("Number of rounds: %u.\n", TESTROUNDS);

  ecc_elapsed_time = ecc_sign((uint8_t*)TEST_MESSAGE, (size_t)TEST_MESSAGE_LEN,
                              private_key, &curve, (unsigned)TESTROUNDS);

  printf("Average Elapsed Time: %u microseconds",
         (unsigned int)ecc_elapsed_time);
  printf("\n====== ECC SIGN ALGORITHM TEST STOP  =====\n");

  // TEST AES SIGN ALGORITHM ELAPSED TIME
  printf("\n====== AES CMAC ALGORITHM TEST START =====\n");
  printf("Number of rounds: %u.\n", TESTROUNDS);

  // uint32_t aes_cmac(const uint8_t *msg, size_t msg_size, uint8_t *key,
  // unsigned testrounds);
  aes_elapsed_time = aes_cmac((uint8_t*)TEST_MESSAGE, (size_t)TEST_MESSAGE_LEN,
                              aes_key, (unsigned)TESTROUNDS);
  //
  printf("Average Elapsed Time: %u microseconds",
         (unsigned int)aes_elapsed_time);
  printf("\n====== AES CMAC ALGORITHM TEST STOP  =====\n");

  return 0;
}
