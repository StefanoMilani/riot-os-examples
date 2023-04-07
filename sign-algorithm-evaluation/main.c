/**
 * @file        main.c
 * @brief       Performance Evaluation of Signign Algorithm
 *
 * @author      Stefano Milani <milani@diag.uniroma1.it>
 *
 */

#include "utils.h"

int main(void) {
	
  printf("micro-ecc compiled!\n");

	uECC_Curve curve = uECC_secp256r1();

  int res;

  // Curve and private key size
  int private_key_size = uECC_curve_private_key_size(curve);
  printf("Private key size: %d\n", private_key_size);
  // Public key size
  int public_key_size = uECC_curve_public_key_size(curve);
  printf("Public key size: %d\n", public_key_size); 

  uint8_t private_key[curve_size];

  uint8_t public_key[public_key_size];

  // Create the key pair
  res = make_ecc_keys(public_key, private_key, &curve);
  ERROR_HANDLER(res, "Failed to create key pair!");

  // Print the private key
  printf("\n\nPrivate key: \n");
  print_key(private_key, private_key_size);

  // Print the public key
  printf("\n\nPublic key: \n");
  print_key(public_key, public_key_size);

  printf("\n");
    
  return 0;
 
}
