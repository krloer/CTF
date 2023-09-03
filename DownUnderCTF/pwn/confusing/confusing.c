#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main() {
    init();

    short d;
    double f;
    char s[4];
    int z; 

    printf("Give me d: ");
    scanf("%lf", &d); // short d; d == 13337

    printf("Give me s: ");
    scanf("%d", &s); // char s[4]; strncmp(s, "FLAG", 4)

    printf("Give me f: ");
    scanf("%8s", &f); // double f; f == 1.6180339887

    if(z == -1 && d == 13337 && f == 1.6180339887 && strncmp(s, "FLAG", 4) == 0) {
        system("/bin/sh");
    } else {
        puts("Still confused?");
    }
}
