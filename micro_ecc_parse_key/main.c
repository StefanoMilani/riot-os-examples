/**
 * @file		maic.c
 * @brief       Test create public key from manually generated private key
 *
 * @author      Stefano Milani <stefano.milani96@gmail.com>
 *
 */

#define uECC_ENABLE_VLI_API 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "uECC.c"


#define TESTROUNDS  16

void print_key(uint8_t* key, size_t size) {
	for(size_t i = 0; i < size; i++) {
		if(i%5==0) 
			printf("\n");
		printf("0x%x\t",key[i]);
	}
	printf("\n");
}

int main(void) {
    printf("micro-ecc compiled!\n");

	const struct uECC_Curve_t *curve = uECC_secp256k1();
	

    size_t curve_size = uECC_curve_private_key_size(curve);
    size_t public_key_size = uECC_curve_public_key_size(curve);
	
	
    
	printf("Private key size: %d\n", curve_size);
    printf("Public key size: %d\n", public_key_size);

    // First key pair
    uint8_t private1[] = {
        0x9b, 0x4c, 0x4b, 0xa0, 0xb7, 0xb1, 0x25, 0x23,
        0x9c, 0x09, 0x85, 0x4f, 0x9a, 0x21, 0xb4, 0x14,
        0x70, 0xe0, 0xce, 0x21, 0x25, 0x00, 0xa5, 0x62,
        0x34, 0xa4, 0x25, 0xf0, 0x0f, 0x00, 0xeb, 0xe7,
    };
    uint8_t public1[public_key_size];
	
	uECC_compute_public_key(private1, public1, curve);
	
	printf("\nFirst Public Key: \n");
	print_key(public1, public_key_size);

    // Compressed public key
    uint8_t compressed_key[curve_size+1];
    uECC_compress(public1, compressed_key, curve);

    printf("\nCompressed public key: \n");
    print_key(compressed_key, curve_size+1);

    // Fill char* buf with your key
    char buf[curve_size+1];
    memcpy(buf, compressed_key, curve_size+1);


    printf("\nCompressed key as char*:\n");
    print_key((uint8_t *)buf, curve_size+1);

    // Re-fill uint8_t* buf
    uint8_t buf8[curve_size+1];
    for(size_t i = 0 ; i < curve_size+1 ; i++) {
        buf8[i] = (uint8_t) buf[i];
    }
    
    printf("\nCompressed key as uint8_t*:\n");
    print_key(buf8, curve_size+1);

}
