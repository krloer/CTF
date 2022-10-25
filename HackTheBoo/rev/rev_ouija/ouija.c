#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
  int iVar1;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  char *local_20;
  int local_14;
  int local_10;
  int local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  local_20 = strdup("ZLT{Svvafy_kdwwhk_lg_qgmj_ugvw_escwk_al_wskq_lg_ghlaearw_dslwj!}");
  puts("Retrieving key.");
  for (local_c = 1; local_c < 0x1e; local_c = local_c + 1) {
    if (local_c % 5 == 0) {
      printf("\r     ");
    }
    putchar(0x2e); //prints flag
  }
  printf("%s", local_20);
  puts(" done!");
  iVar1 = 13; //key
  puts("Hmm, I don\'t like that one. Let\'s pick a new one.");
  for (local_10 = 1; local_10 < 0x1e; local_10 = local_10 + 1) {
    if (local_10 % 5 == 0) {
      printf("\r     ");
    }
    putchar(0x2e);
  }
  puts(" done!");
  iVar1 = iVar1 + 5;
  puts("Yes, 18 will do nicely.");
  for (local_14 = 1; local_14 < 0x14; local_14 = local_14 + 1) {
    if (local_14 % 5 == 0) {
      printf("\r     ");
    }
    putchar(0x2e);
  }
  puts(" done!");
  puts("Let\'s get ready to start. This might take a while!");
  for (local_24 = 1; local_24 < 0x32; local_24 = local_24 + 1) {
    if (local_24 % 5 == 0) {
      printf("\r     ");
    }
    putchar(0x2e);
  }
  puts(" done!");
  for (; *local_20 != '\0'; local_20 = local_20 + 1) {
    if ((*local_20 < 'a') || ('z' < *local_20)) {
      if ((*local_20 < 'A') || ('Z' < *local_20)) {
        puts("We can leave this one alone.");
        for (local_38 = 1; local_38 < 10; local_38 = local_38 + 1) {
          if (local_38 % 5 == 0) {
            printf("\r     ");
          }
          putchar(0x2e);
        }
        puts(" done!");
      }
      else {
        puts("This one\'s an uppercase letter!");
        for (local_30 = 1; local_30 < 0x14; local_30 = local_30 + 1) {
          if (local_30 % 5 == 0) {
            printf("\r     ");
          }
          putchar(0x2e);
        }
        puts(" done!");
        if (*local_20 - iVar1 < 0x41) {
          puts("Wrapping it round...");
          for (local_34 = 1; local_34 < 0x32; local_34 = local_34 + 1) {
            if (local_34 % 5 == 0) {
              printf("\r     ");
            }
            putchar(0x2e);
          }
          puts(" done!");
          *local_20 = *local_20 + '\x1a';
        }
        *local_20 = *local_20 - (char)iVar1;
      }
    }
    else {
      puts("This one\'s a lowercase letter");
      for (local_28 = 1; local_28 < 0x14; local_28 = local_28 + 1) {
        if (local_28 % 5 == 0) {
          printf("\r     ");
        }
        putchar(0x2e);
      }
      puts(" done!");
      if (*local_20 - iVar1 < 0x61) {
        puts("Wrapping it round...");
        for (local_2c = 1; local_2c < 0x32; local_2c = local_2c + 1) {
          if (local_2c % 5 == 0) {
            printf("\r     ");
          }
          putchar(0x2e);
        }
        puts(" done!");
        *local_20 = *local_20 + '\x1a';
      }
      *local_20 = *local_20 - (char)iVar1;
    }
    puts(
        "Okay, let\'s write down this letter! This is a pretty complex operation, you might want to  check back later."
        );
    for (local_3c = 1; local_3c < 300; local_3c = local_3c + 1) {
      if (local_3c % 5 == 0) {
        printf("\r     ");
      }
      putchar(0x2e);
    }
    puts(" done!");
    printf("%c\n",(unsigned long)(unsigned int)(int)*local_20);
  }
  puts("You\'re still here?");
  return 0;
}