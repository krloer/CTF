#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
	while (1) {
		system("python chall_obf.cpython-310.pyc");
		char flag[6] = {'f','l','a','g','{'};
		char in[200] = {0};
		scanf("%s", &in);
		strcat(flag, in);
		//sleep(0);
		puts(flag);
	}
	return 0;
}
