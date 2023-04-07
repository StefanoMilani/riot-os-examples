#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #define default_RNG_defined 0

#include "tinycrypt/ecc_dh.h"
#include "random.h"
#include "xtimer.h"

#define TESTROUNDS 16

void print_key(uint8_t* key, int size) {
    for(int i = 0; i < size; i++) {
        if(i%5 == 0)
            printf("\n");
        printf("0x%x\t", key[i]);
    }
    printf("\n");
}

int my_random_function(uint8_t *dest, size_t size){
    random_init(xtimer_now_usec());
    random_bytes(dest, size);
    return 1;
}

int main(void){
    // Initialize curve
    uECC_Curve curve = uECC_secp256r1();
    // Get keys sizes
    int curve_size = uECC_curve_private_key_size(curve);
    int public_key_size = uECC_curve_public_key_size(curve);
    // Printf keys sizes
    printf("Private key size: %d\n", curve_size);
    printf("Public key size: %d\n", public_key_size);

    // Initialize keys buffer
    uint8_t private[curve_size];
    uint8_t public[public_key_size];
    for (int i = 0 ; i < TESTROUNDS ; i++) {
        // Create private key
        my_random_function(private, curve_size);
        // Create public key
        uECC_compute_public_key(private, public, curve);
        // Print keys
        printf("Private key:");
        print_key(private, curve_size);
        printf("Public key:");
        print_key(public, public_key_size);
        if(uECC_valid_public_key(public, curve)){
            printf("Public key not valid!\n");
            return -1;
        } 
        printf("Public key valid!!\n");
    }
    
    printf("\n- Generation of key pair seems to work!!! \n");

    // Testing shared secret generation
    uint8_t private2[curve_size];
    uint8_t public2[public_key_size];
    uint8_t secret1[curve_size];
    uint8_t secret2[curve_size];

    for(int i = 0 ; i < TESTROUNDS ; i++) {
        my_random_function(private, curve_size);
        uECC_compute_public_key(private, public, curve);
        my_random_function(private2, curve_size);
        uECC_compute_public_key(private2, public2, curve);

        uECC_shared_secret(public2, private, secret1, curve);
        uECC_shared_secret(public, private2, secret2, curve);

        if(memcmp(secret1, secret2, curve_size)) {
            printf("Secret generation failed!!\n");
            return -1;
        } 
        printf("Secret generation goes well!!\n");
    }
    printf("\n- Secret generation works!!\n");
    return 0;
}

