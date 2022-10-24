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

int main()
{
    char buffer[16];
    int value = 4919;
    ignore_me_init_buffering();
    ignore_me_init_signal();
    printf("There is a variable on the stack called 'value'. Overflow it to gain a shell! Enter your payload:\n");
    fgets(buffer, 32, stdin);
    if (value != 4919)
    {
        printf("Content of 'value' is now: '%x'. You overwrote it! Here comes the shell\n", value);
        system("/bin/sh");  
    }
    else
    {
        printf("Content of 'value' is still: '%x'. You need to overwrite it!", value);
    }
    return 0;
}