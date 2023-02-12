printf("Question #3: What\'s the integral of 1/cabin dcabin? ");
fflush(stdout);
getchar();
fgets(local_118,0x100,stdin);
sVar2 = strcspn(local_118,"\n");
local_118[sVar2] = '\0';
for (local_10 = local_118; *local_10 != '\0'; local_10 = local_10 + 1) {
      *local_10 = (char)((long)(*local_10 * 0x11) % 0xfd);
}


enc = "0e c9 9d b8 26 83 26 41 74 e9 26 a5 83 94 0e 63 37 37 37"

putchar(10);
iVar1 = strcmp(local_118,enc);
if (iVar1 == 0) {
      puts("Wow! A 100%! You must be really good at math! Here, have a flag as a reward.");
  print_flag();
}