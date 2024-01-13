#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

char* flag = "That is more than enough! Here is your flag: flag{aaaaaaaaaaaaaaaaaaaaaaaaaaa}";

void ignore_me_init_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig) {
    if (sig == SIGALRM) {
        printf("[!] Anti DoS Signal. Patch me out for testing.");
        _exit(0);
    }
}

void ignore_me_init_signal() {
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}

void printFlag() {
    puts(flag);
    return;
}

void win(int amount)  {
    if (amount > 0x100000000) {
        printFlag();
    }
    else {
        printf("sorry, %d is not enough to win in this game.\n", amount);
    }
    return;
    
}

int main() {
    ignore_me_init_buffering();
    ignore_me_init_signal();
    char input[60];
    printf("Welcome to pay2win, the classical game where you can pay your way to victory!\n");
    printf("How much are you willing to pay > ");
    fgets(input, 0x60, stdin);
    int sum = atoi(input);
    win(sum);

    return 0;
}
