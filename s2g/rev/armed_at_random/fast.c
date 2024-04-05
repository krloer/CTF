#include <stdlib.h>
#include <stdio.h>

int main() {
  int iVar1;
  int iVar2;
  int iVar3;
  
  srand(0);
  iVar1 = rand();
  if (iVar1) {
    iVar1 = rand();
    iVar2 = rand();
    iVar3 = rand();
    printf("S2G{%x%x%x}\n",iVar1,iVar2,iVar3);
  }
  return 0;
}