#include <stdio.h>

int main() {
    char flag[24];
    long double word[23];

    word[15] = 91.0;
    word[18] = 91.0;
    word[0]  = 130.0 - 11.0;
    word[23] = 127.0 - 6.0;
    word[1] = 396.0 / 6.0;
    word[22] = 104.0;
    word[2] = 72.0;
    word[21] = 44.0;
    word[3] = 67.0;
    word[20] = 44.0;
    word[4] = 54.0;
    word[19] = (word[3] + word[20]) - 16.0;
    word[5] = 44.0;
    word[17] = 49.0;
    word[6] = 33.0; //(40.5 - 15.0 * 0.1666666666666667)/(7.0 * 0.1666666666666667);
    word[16] = 45.0;
    word[7] = 47.0;
    word[14] = 96.0;
    word[8] = 110.0;
    word[13] = word[14] / 2.0 - 1.0;
    word[9] = 104.0;
    word[11] = 108.0;
    word[12] = word[11];
    word[10] = 48.0;

    for (int i = 0; i < 24; i++)
    {
        flag[i] = (char) word[i];
    }


    for (int local_c = 0; (unsigned long)(long)local_c < 24; local_c = local_c + 1) {
          word[local_c] = (double)(int)flag[(long)local_c];
        //   printf("%d\n", flag[local_c]);
    }

    int uVar2 = 0;

    for (double i = 1.0; i < 128; i++)
    {
        word[6] = i;
        if ((word[6] * 8.0 + 15.0) * 0.1666666666666667 ==
        (word[6] + word[6] + 81.0) * 0.5) {
            printf("good");
            break;
        }
    }

    word[6] = (40.5 - 15.0 * 0.1666666666666667)/7.0 * 0.1666666666666667;
    
    if ((word[6] * 8.0 + 15.0) * 0.1666666666666667 ==
        (word[6] + word[6] + 81.0) * 0.5) {
        printf("good");
    }
    else {
        printf("%s", "Bad");
        uVar2 = 1;
    }

    printf("%d", word[6]);
                                  

    return 0;
}   
    