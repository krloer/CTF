#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    int res;
    char input[10];
    
    fgets(input,10,stdin);
    res = atoi(input);
    printf("String value = %s, Int value = %d\n", input, res);
 
    return(0);
} 