/**
 * @file        utils.h
 * @brief       Performance Evaluation of Signign Algorithm
 *
 * @author      Stefano Milani <milani@diag.uniroma1.it>
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "random.h"
#include "xtimer.h"
#include "hashes/sha256.h"
#include "uECC.h"
#include "hashes/aes128_cmac.h"

#define ERROR_HANDLER(res, message) 	do{\
											if(!res){ \
												fprintf(stderr, "%s\n", message); \
												exit(1); \
											} \
										}while(0); \
										
void print_key(uint8_t* key, int size);

int make_ecc_keys(uint8_t *public_key, uint8_t *private_key, uECC_Curve *curve);

uint32_t ecc_sign(uint8_t *msg, size_t msg_size, const uint8_t *private_key, uECC_Curve *curve, unsigned testrounds);

uint32_t aes_cmac(const uint8_t *msg, size_t msg_size, uint8_t *key, unsigned testrounds);
