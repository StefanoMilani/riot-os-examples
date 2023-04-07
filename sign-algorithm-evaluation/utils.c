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

uECC_RNG_Function rng_function(uint8_t *dest, unsigned size) {
  random_bytes(dest, size);
  return 1;
}

int make_ecc_keys(uint8_t *public_key, uint8_t *private_key, uECC_Curve *curve) {
  uECC_set_rng(&rng_function);
  return uECC_make_key(public_key, private_key, *curve);
}
