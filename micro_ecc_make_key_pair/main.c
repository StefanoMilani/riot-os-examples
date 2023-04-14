/**
 * @file		main.c
 * @brief       Public/private key pair generation for ECC
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#include "utils.h"

int main(void) {
  printf("micro-ecc compiled!\n");

  uECC_Curve curve = uECC_secp256r1();
  int res;

  // Curve and private key size
  int curve_size = uECC_curve_private_key_size(curve);
  printf("Private key size: %d\n", curve_size);
  // Public key size
  int public_key_size = uECC_curve_public_key_size(curve);
  printf("Public key size: %d\n", public_key_size);

  printf("Testing %d random private key pairs and signature using HWRNG\n",
         TESTROUNDS);

  uint8_t private[curve_size];

  uint8_t public[public_key_size];

  uint8_t compressed[curve_size + 1];

  uint8_t decompressed[public_key_size];

  // Create the key pair
  res = uECC_make_key(public, private, curve);
  ERROR_HANDLER(res, "Failed to create key pair!");

  // Print the private key
  printf("\n\nPrivate key: \n");
  print_key(private, curve_size);

  // Print the public key
  printf("\n\nPublic key: \n");
  print_key(public, public_key_size);

  // Compress public key
  uECC_compress(public, compressed, curve);
  printf("\n\nCompressed public key: \n");
  print_key(compressed, curve_size + 1);

  // Decompress key
  uECC_decompress(compressed, decompressed, curve);
  printf("\n\nDecompressed public key: \n");
  print_key(decompressed, public_key_size);

  // Check if public key and decompressed public key are equals

  if (!memcmp(public, decompressed, public_key_size))
    printf("\n\nCompression and decompression worked\n");
  else
    printf("\n\nCompression and decompression NOT worked\n");

  // Print curve->G
  // 	printf("\n\nPoint G of curve: \n");
  // 	for(int i = 0; i<public_key_size;i++) {
  // 		if(i%5 == 0)
  // 			printf("\n");
  // 		printf("0x%x\t", (*curve).G[i]);
  // 	}

  printf("\n");

  return 0;
}
