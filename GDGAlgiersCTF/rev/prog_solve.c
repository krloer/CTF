#include <stdio.h>
#include <stdlib.h>

int main() {
    char input [48];
    unsigned int arr [47];
    int num;
    int l20;
    int i = 0;
    int put;
    int p;
    arr[0] = 0x15; // 00010101 = 01010110 ^ 01000011 67 C
    arr[1] = 0x91; 
    arr[2] = 0x2a; 
    arr[3] = 0x59; 
    arr[4] = 0x72;
    arr[5] = 0x1e;
    arr[6] = 0xd9;
    arr[7] = 10;
    arr[8] = 0xb6;
    arr[9] = 0xf1;
    arr[10] = 0x2a;
    arr[11] = 0xba;
    arr[12] = 0x5f;
    arr[13] = 0x66;
    arr[14] = 0x70;
    arr[15] = 0x61;
    arr[16] = 0x4f;
    arr[17] = 0xf7;
    arr[18] = 0xd1;
    arr[19] = 0x49;
    arr[20] = 0xd6;
    arr[21] = 0xac;
    arr[22] = 0xb4;
    arr[23] = 0x21;
    arr[24] = 0xb2;
    arr[25] = 0x1e;
    arr[26] = 0x94;
    arr[27] = 0x28;
    arr[28] = 0x5a;
    arr[29] = 0x57;
    arr[30] = 0xaa;
    arr[31] = 0x15;
    arr[32] = 199;
    arr[33] = 10;
    arr[34] = 200;
    arr[35] = 0xa3;
    arr[36] = 0xf0;
    arr[37] = 0x76;
    arr[38] = 3;
    arr[39] = 0x34;
    arr[40] = 0x88;
    arr[41] = 0xe1;
    arr[42] = 0x24;
    arr[43] = 99;
    arr[44] = 0xc2;
    arr[45] = 0x13;
    arr[46] = 0x5a;
    arr[47] = 2;
    srand(0x7e6);
    while(i <= 47) {
        num = rand();
        l20 = (unsigned int) (num >> 0x1f) >> 0x18;

        int local_20 = 0;
        local_20 = (num + local_20 & 0xff) - local_20; // 

        p = arr[i] ^ local_20;
        char put = p;

        printf("%c", p);

        i++;
    } 

    return 0;
}