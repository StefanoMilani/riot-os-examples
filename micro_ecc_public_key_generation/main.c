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
#include "uECC.h"


#define TESTROUNDS  16

typedef struct uECC_Curve_t* ECC_Curve;

void print_key(uint8_t* key, int size) {
	for(int i = 0; i < size; i++) {
		if(i%5==0) 
			printf("\n");
		printf("0x%x\t",key[i]);
	}
	printf("\n");
}

int main(void) {
    printf("micro-ecc compiled!\n");

	const struct uECC_Curve_t *curve1 = uECC_secp256k1();
    const struct uECC_Curve_t *curve2 = uECC_secp256k1();	

    int curve_size = uECC_curve_private_key_size(curve1);
    int public_key_size = uECC_curve_public_key_size(curve1);
    
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

	uECC_compute_public_key(private1, public1, curve1);
	
	printf("\nFirst Public Key: \n");
	print_key(public1, public_key_size);
	
	// Second key pair
    uint8_t private2[] = {
        0xb5, 0x45, 0xaf, 0xa0, 0x2e, 0x5c, 0xa6, 0x17,
        0x3b, 0x5a, 0x55, 0x76, 0x67, 0x5d, 0xd4, 0x5e,
        0x41, 0x7c, 0x4f, 0x19, 0x9f, 0xb9, 0x75, 0xdc,
        0xba, 0x57, 0xc4, 0xa2, 0x26, 0xc6, 0x86, 0x2a,
    };
    uint8_t public2[public_key_size];

    uECC_compute_public_key(private2, public2, curve2);

	// Print the public key
	printf("\nSecond Public Key: \n");
	print_key(public2, public_key_size);

    // Compare compressed key
    uint8_t compr1[curve_size+1], compr2[curve_size+1];
    uint8_t decompr1[public_key_size], decompr2[public_key_size];

    uECC_compress(public1, compr1, curve1);
    uECC_decompress(compr1, decompr1, curve2);

    if(memcmp(public1, decompr1, public_key_size))
        printf("Compression and decompression failed on first public key!!\n");
    else
        printf("First pub OK!\n");

    printf("\nPrint the first decompressed key!\n");
    print_key(decompr1, public_key_size);
    printf("And the original first pub key:\n");
    print_key(public1, public_key_size);

    uECC_compress(public2, compr2, curve2);
    uECC_decompress(compr2, decompr2, curve1);

    if(memcmp(public2, decompr2, public_key_size))
        printf("Compression and decompression failed on second public key!!\n");
    else
        printf("Second pub OK!\n");
    
    printf("\nPrint the second decompressed key!\n");
    print_key(decompr2, public_key_size); 
    printf("And the original second pub key:\n");
    print_key(public2, public_key_size);

    // Compare secret
    uint8_t secret1[curve_size], secret2[curve_size];

    uECC_shared_secret(public2, private1, secret1, curve1);
    printf("Secret 1:\n");
    print_key(secret1, curve_size);
    uECC_shared_secret(public1, private2, secret2, curve2);
    printf("Secret 2:\n");
    print_key(secret2, curve_size);
    if(memcmp(secret1, secret2, curve_size))
        printf("Secrets creation failed!\n");
    else
        printf("Secrets creation successfull!\n");
    

    return 0;
}


