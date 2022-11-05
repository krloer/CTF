#include <stdio.h>

int main() {
    int i = 0;
    int j = 0;

    for (i = 0; i < 7; i = i + 1) {
        for (j = 0; j < 7; j = j + 1) {
          printf("%ld\n", ((long)i * 7 + (long)j) * 4); 
        }
    }

    return 0;
}