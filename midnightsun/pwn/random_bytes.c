#include <stdlib.h>
#include <stdio.h>
#include <byteswap.h>

int main(int argc, char *argv[]) {
    unsigned long int seed;
    scanf("%lx", &seed);
    srand(seed);
    for (int i = 0; i < 0x4000000; i++) {
        int num = rand();
        printf("%08x", __bswap_32(num));
    }
    printf("\n");

    return 0;
}