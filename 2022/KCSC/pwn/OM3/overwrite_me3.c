#include <string.h>
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
    char buffer[32];

    ignore_me_init_buffering();
    ignore_me_init_signal();
	
    printf("You now know how to hit payloads on offsets. Use this knowledge to force a win out of this program!\n\n");
	printf("Let's play. Guess a number between 1-10:\n");

	fgets(buffer, 64, stdin);

	if (strcmp(buffer, "5\n") != 0)
	{
		lose();
	}
	else
	{
		lose_again();
	}

	return 0;

}

lose()
{
	printf("Wrong. You lose!\n");
}

lose_again()
{
	printf("Pfft. Also wrong. You lose again!\n");
}

win()
{
	printf("Correct! You won! Here comes the shell\n");
	system("/bin/sh");
}



