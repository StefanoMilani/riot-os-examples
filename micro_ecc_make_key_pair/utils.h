#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "uECC.h"
#include "periph/hwrng.h"

#define TESTROUNDS  16

#define ERROR_HANDLER(res, message) 	do{\
											if(!res){ \
												fprintf(stderr, "%s\n", message); \
												exit(1); \
											} \
										}while(0); \
										
void print_key(uint8_t* key, int size);


