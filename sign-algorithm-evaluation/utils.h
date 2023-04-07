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
#include "uECC.h"

#define TESTROUNDS  16

#define ERROR_HANDLER(res, message) 	do{\
											if(!res){ \
												fprintf(stderr, "%s\n", message); \
												exit(1); \
											} \
										}while(0); \
										
void print_key(uint8_t* key, int size);

int make_ecc_keys(uint8_t *public_key, uint8_t *private_key, uECC_Curve *curve);
