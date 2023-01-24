undefined8 main(void)

{
  undefined4 uVar1;
  int iVar2;
  long in_FS_OFFSET;
  int i;
  int j;
  undefined local_108 [208];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init_buffering();
  printf("Enter your name:\n> ");
  fgets(local_38,0x28,stdin);
  uVar1 = e(local_38);
  printf("Enter registration key\n> ");
  for (i = 0; i < 7; i = i + 1) {
    for (j = 0; j < 7; j = j + 1) {
      __isoc99_scanf("%d",local_108 + ((long)i * 7 + (long)j) * 4); 
    }
  }
  iVar2 = a(local_108,uVar1);
  if (iVar2 == 0) {
    puts("that is not correct!");
  }
  else {
    success();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}