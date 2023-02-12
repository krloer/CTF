#include <stdio.h>

long int func8(long int arg8) {
    arg8 += 2; 
    return arg8;
}

long int func7(long int arg7) {
    if (arg7 < 100)
    {
        arg7 = 7;
    }
    return arg7;
}

long int func5(long int arg5) {
    arg5 = func8(arg5);
    return arg5;
}

long int func4(long int arg4) {
    arg4 = 17;
    return arg4;
}

long int func3(long int arg3) {
    arg3 = func7(arg3);
    return arg3;
}

long int func2(long int arg2) {
    if (arg2 > 499)
    {
        arg2 += 13; 
        arg2 = func5(arg2);
    } else {
        arg2 -= 86;
        arg2 = func4(arg2);
    }
    
    return arg2;
}

long func1(long int arg1) {
    if (arg1 < 100)
    {
        arg1 = func3(arg1);
    } else
    {
        arg1 += 100;
        arg1 = func2(arg1);
    }

    return arg1;
}

int main() {
    long int arg = 3964545182;
    arg = func1(arg);

    printf("%ld\n", arg);
    printf("picoCTF{%lx}", arg);
    
    return 0;
}