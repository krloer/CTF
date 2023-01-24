undefined8 main(void)

{
  long lVar1;
  undefined8 uVar2;
  char *pcVar3;
  size_t sVar4;
  double word [4];
  double word[4];
  double word[5];
  double word[6];
  double word[7];
  double word[8];
  double word[9];
  double word[10];
  double word[11];
  double word[12];
  double word[13];
  double word[14];
  double word[15];
  double word[16];
  double word[17];
  double word[18];
  double word[19];
  double word[20];
  double word[21];
  double word[22];
  double word[23];
  char input [257];
  size_t local_18;
  int local_10;
  int local_c;
  
  lVar1 = ptrace(PTRACE_TRACEME,0);
  if (lVar1 < 0) {
    puts("Please, do not use a debugger");
    uVar2 = 1;
  }
  else {
    puts(
        "\n  _____ __    _____ _____\n  |     |  |  |   __|     |\n  | | | |  |__|   __| | | |\n  |_ |_|_|_____|_____|_|_|_|\n  v1.0 - Poeta Errante\n\n"
        );
    puts(
        "  ,-.       _,---._ __  / \\\n /  )    .-\'       `./ /   \\\n(  (   ,\'            `/    / |\n \\  `-\"             \\\'\\   / |\n  `.              ,  \\ \\ /  |\n   /`.          ,\'- `----Y   |\n  (            ;        |   \'\n  |  ,-.    ,-\'         |  /\n  |  | (   |             | /\n  )  |  \\  `.___________|/\n  `--\'   `--\'\n\n"
        );
    puts("~ Help Wesley the cat to find the right word :3 ~\n\n");
    printf("~ Insert a word: ");
    pcVar3 = fgets(input + 1,0xff,stdin);
    if (pcVar3 == (char *)0x0) {
      puts("Insert a word");
      uVar2 = 0;
    }
    else {
      sVar4 = strlen(input + 1);
      input[sVar4] = '\0';
      local_18 = strlen(input + 1);
      if (local_18 == 0x18) {
        for (local_c = 0; (ulong)(long)local_c < local_18; local_c = local_c + 1) {
          word[local_c] = (double)(int)input[(long)local_c + 1];
        }
        if (word[15] == 91.0) {
          if (word[18] == 91.0) {
            if (word[0] + word[0] + 11.0 == word[0] + 130.0) {
              if (word[23] + word[23] + 6.0 == word[23] + 127.0) {
                if (word[1] * 7.0 == word[1] + 396.0) {
                  if (word[22] == 104.0) {
                    if ((word[2] + 2.0) * 3.0 - 2.0 == (word[2] - 17.0) * 4.0) {
                      if (word[21] == (word[21] + word[21]) - 44.0) {
                        if (word[3] == 67.0) {
                          if ((word[20] * 3.0 - 2.0) * 3.0 - (word[20] * 5.0 + 2.0) * 4.0 ==
                              word[20] * -8.0 - 146.0) {
                            if ((word[4] * 5.0 - 2.0) * 5.0 - (word[4] + word[4] + 7.0) * 6.0
                                == word[4] * 33.0 - 1132.0) {
                              if (word[19] == (word[3] + word[20]) - 16.0) {
                                if ((word[5] + word[5]) / 3.0 == (word[5] + 44.0) / 3.0) {
                                  if (word[17] == 49.0) {
                                    if ((word[6] * 8.0 + 15.0) * 0.1666666666666667 ==
                                        (word[6] + word[6] + 81.0) * 0.5) {
                                      if (0.0 - word[16] / 5.0 == 36.0 - word[16]) {
                                        if ((word[7] * 7.0) / 2.0 == word[7] * 3.0 + 23.5) {
                                          if (word[14] == word[14] / 2.0 + 48.0) {
                                            if (word[8] == 110.0) {
                                              if (word[13] == word[14] / 2.0 - 1.0) {
                                                if (word[9] == 104.0) {
                                                  if ((word[12] == word[11]) &&
                                                     (word[11] == 108.0)) {
                                                    if (word[10] == 48.0) {
                                                      puts(
                                                  "Word found! But it\'s not the flag. Awww :3");
                                                  for (local_10 = 0;(ulong)(long)local_10 < local_18;local_10 = local_10 + 1) {
                                                    FUN_00101188((int)(char)(int)word[local_10]);
                                                  }
                                                  uVar2 = 0;
                                                  }
                                                  else {
                                                    not_found();
                                                    uVar2 = 1;
                                                  }
                                                  }
                                                  else {
                                                    not_found();
                                                    uVar2 = 1;
                                                  }
                                                }
                                                else {
                                                  not_found();
                                                  uVar2 = 1;
                                                }
                                              }
                                              else {
                                                not_found();
                                                uVar2 = 1;
                                              }
                                            }
                                            else {
                                              not_found();
                                              uVar2 = 1;
                                            }
                                          }
                                          else {
                                            not_found();
                                            uVar2 = 1;
                                          }
                                        }
                                        else {
                                          not_found();
                                          uVar2 = 1;
                                        }
                                      }
                                      else {
                                        not_found();
                                        uVar2 = 1;
                                      }
                                    }
                                    else {
                                      not_found();
                                      uVar2 = 1;
                                    }
                                  }
                                  else {
                                    not_found();
                                    uVar2 = 1;
                                  }
                                }
                                else {
                                  not_found();
                                  uVar2 = 1;
                                }
                              }
                              else {
                                not_found();
                                uVar2 = 1;
                              }
                            }
                            else {
                              not_found();
                              uVar2 = 1;
                            }
                          }
                          else {
                            not_found();
                            uVar2 = 1;
                          }
                        }
                        else {
                          not_found();
                          uVar2 = 1;
                        }
                      }
                      else {
                        not_found();
                        uVar2 = 1;
                      }
                    }
                    else {
                      not_found();
                      uVar2 = 1;
                    }
                  }
                  else {
                    not_found();
                    uVar2 = 1;
                  }
                }
                else {
                  not_found();
                  uVar2 = 1;
                }
              }
              else {
                not_found();
                uVar2 = 1;
              }
            }
            else {
              not_found();
              uVar2 = 1;
            }
          }
          else {
            not_found();
            uVar2 = 1;
          }
        }
        else {
          not_found();
          uVar2 = 1;
        }
      }
      else {
        puts("Maybe you should search for a different length word! Meeoww");
        uVar2 = 1;
      }
    }
  }
  return uVar2;
}