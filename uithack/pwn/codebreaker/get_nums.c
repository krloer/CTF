#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    srand(atol(argv[1]));
    int a = rand()%34;
    a = rand()%34;
    a = rand()%34;
    a = rand()%34;

    int winning_numbers[3] = {rand()%34, rand()%34, rand()%34};
    printf("%d %d %d\n", winning_numbers[0], winning_numbers[1], winning_numbers[2]);
    return 0;
}