#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void ignore_me_init_buffering() {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
    }   
void kill_on_timeout(int sig) {
    if (sig == SIGALRM) {
        printf("[!] Anti DoS Signal. Patch me out for testing.");
        exit(0);
    }
}
void ignore_me_init_signal() {
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}

int main() {

    char buffer[64];

    ignore_me_init_buffering();
    ignore_me_init_signal();

    printf("Do you like shellcode? I do. Give me your best shellcode (max 64 bytes) and I'll run it!\n");

    read(0, buffer, 64);

    ((void (*)()) (buffer))();
}