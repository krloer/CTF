#include <stdio.h>
#include <string.h>


int main()
{
    char shellcode[500];
    scanf("%s", &shellcode);
	printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();

	return 0;
}