#include <stdio.h>
#include <stdlib.h>

int rc4(int param_1,int param_2)
{
  return (param_2 + param_1) % 0x100;
}

int main() {
  int local_18 = rand();
  srand(local_18);
  for (int i = 0; i < 10; i = i + 1) {
    int iVar1 = rand();
    int uVar2 = (iVar1 + local_18) % 0x100;
    printf("%d\n", uVar2);
  }
}

