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
    int value = 0x0;

    ignore_me_init_buffering();
    ignore_me_init_signal();
	
    printf("Find the offset and overflow the stack-variable 'value' correctly. Enter your payload:\n");

	fgets(buffer, 32, stdin);

	if (value == 0x4e5750)
	{
        printf("Content of 'value' is now: '%x'. You found the offset and key! Here comes the shell\n", value);
        system("/bin/sh");	
	}

	else if (value == 0x50574e)
	{
		printf("You hit the offset, but did you remember to take endianess into account? No shell for you yet!");
	}
    
	else
	{
    	printf("Oof. Missed the offset or correct overwrite! 'value' is 0x%x Try again", value);
	}

	return 0;

}

