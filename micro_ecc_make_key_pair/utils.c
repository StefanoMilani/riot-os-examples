#include "utils.h"

void print_key(uint8_t* key, int size) {
	for(int i = 0; i < size; i++) {
		if(i%5==0) 
			printf("\n");
		printf("0x%x\t",key[i]);
	}
}
