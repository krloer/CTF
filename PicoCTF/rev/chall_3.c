#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    unsigned int arg = atoi(argv[1]);

    int a = arg;
    int b = 0;
    while (a != 0)
    {
        if (a % 2 != 0)
        {
            b = b + 3;
        } 
        a = a / 2;
    }

    printf("%ld", b);
}