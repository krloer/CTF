
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
        _exit(0);
    }
}

void ignore_me_init_signal() {
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}
void success()  {
    puts("Well done, here is your flag: "); 
    FILE *fp;
    char buff[255];
    char ch;
    fp = fopen("/opt/flag", "r");
    while((ch = fgetc(fp)) != EOF)
        printf("%c", ch);
    puts("");
    fclose(fp);
}

int fixme = 0;

int main(void){
    ignore_me_init_buffering();
    ignore_me_init_signal();

    char buf[20];
    printf("To get the flag, the fixme variable to 1\n> ");
    fgets(buf, 20, stdin);
    printf(buf);

    if (fixme) {
        success();

    }

}