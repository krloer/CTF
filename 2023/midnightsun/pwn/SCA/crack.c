#include <stdio.h>
#include <stdlib.h>

int main() {
	uint i;

    while(1) {
        if ((uint)(i * 0x213f) % 0x2b27ea == 0x5fa6) {
            printf("%d", i);
            exit(0);
        }
        i++;
    }
}

// gcc -m32 crack.c -o cracking
