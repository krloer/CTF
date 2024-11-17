// Compile:
// gcc baby_bro_pwn.c -o baby_bro_pwn -fno-stack-protector

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void ignore_me_init_buffering(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig)
{
	if (sig == SIGALRM)
	{
		printf("[!] Anti DoS Signal. Patch me out for testing.");
		_exit(0);
	}
}

void ignore_me_init_signal()
{
	signal(SIGALRM, kill_on_timeout);
	alarm(60);
}

struct __attribute__((__packed__)) Dude
{
	char message[32];
	int showFlag;
};

char *FLAG = "EPT{n0t_th1s_fl4g_bruh}";
int main()
{
	struct Dude homie;

	ignore_me_init_buffering();
	ignore_me_init_signal();
	do
	{
		printf("What's up dude?\n> ");
		fgets(homie.message, 37, stdin);

		if (homie.showFlag == 0x47414c46)
		{
			printf("\nYoooo lit af fam!\n");
			sleep(2);
			printf("sick tbh...\n");
			sleep(3);
			printf("legit dude, my broski passed me this msg, you can lowkey get it.\n");
			sleep(3);
			printf("no cap.\n\n");
			sleep(2);
			printf("%s\n", FLAG);
			return 0;
		}
		else
		{
			printf("Damn, cappin bussin, I'm sorry to hear that broman :^(\n\n");
			sleep(2);
			printf("Anyways...\n\n");
			sleep(2);
		}
	} while (1);

	return 0;
}
