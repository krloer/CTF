#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <signal.h>
#include <unistd.h>

/*****
 * IGNORE EVERYTHING BETWEEN THESE COMMENTS.
 * IT IS NOT PART OF THE CHALLENGE.
 *****/
void ignore_me_init_buffering() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void ignore_me_kill_on_timeout(int sig) {
  if (sig == SIGALRM) {
  	printf("[!] Anti DoS Signal. Patch me out for testing.");
    _exit(0);
  }
}

void ignore_me_init_signal() {
	signal(SIGALRM, ignore_me_kill_on_timeout);
	alarm(60);
}
/*****
 * UNTIL HERE.
 *****/



struct User {
	char name[16];
	char rank[16];
};

void run_program() {
	char name[16];
	struct User user;

	printf("Enter your name: ");
	gets(name);

	strcpy(user.rank, "guest");
	strcpy(user.name, name);

	if(!strcmp(user.rank, "manager"))
        printf("%s\n", getenv("FLAG"));
	else {
		printf("You are not authorized to get the flag!\n");
        printf("You need to be a \"manager\".\n");
        printf("You are a \"%s\".\n", user.rank);
    }
}

int main() {
	ignore_me_init_buffering();
	ignore_me_init_signal();
	run_program();
	return 0;
}
