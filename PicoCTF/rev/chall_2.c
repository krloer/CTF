#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    unsigned int arg = atoi(argv[1]);

    int a = arg;
    int b = 0;
    int c = 0;
    while (c < a)
    {
        b = b + 3; //b = arg*3
        c = c + 1;
    }

    //find last 32 bits of b: 
    //b mod 2^32
    //32 fordi 4 bytes * 8

    printf("%ld", b);
}