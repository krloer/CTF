#include <stdio.h>
#include <string.h>

int main() {
    int local_128[40];
    int local_12c;
    char local_79;
    int local_13d;
    int local_13c;
    local_128[0] = 6;
        local_128[1] = 0x3c;
        local_128[2] = 0x27;
        local_128[3] = 0x20;
        local_128[4] = 0x37;
        local_128[5] = 0;
        local_128[6] = 0x37;
        local_128[7] = 0x30;
        local_128[8] = 0x21;
        local_128[9] = 0x2c;
        local_128[10] = 0x31;
        local_128[11] = 0x20;
        local_128[12] = 0x36;
        local_128[13] = 0x3e;
        local_128[14] = 0x61;
        local_128[15] = 0x20;
        local_128[16] = 0;
        local_128[17] = 0x1a;
        local_128[18] = 0x2b;
        local_128[19] = 10;
        local_128[20] = 0x31;
        local_128[21] = 0x2d;
        local_128[22] = 0xc;
        local_128[23] = 0xb;
        local_128[24] = 2;
        local_128[25] = 0x1a;
        local_128[26] = 0xc;
        local_128[27] = 0x61;
        local_128[28] = 0x1a;
        local_128[29] = 0x74;
        local_128[30] = 0x28;
        local_128[31] = 0x35;
        local_128[32] = 0x2a;
        local_128[33] = 0x61;
        local_128[34] = 0x61;
        local_128[35] = 0x2c;
        local_128[36] = 7;
        local_128[37] = 0x29;
        local_128[38] = 0x20;
        local_128[39] = 0x38;
        local_128[40] = '\0';
        local_12c = 0x45;
        for (local_13c = 0; local_13c < 0x28; local_13c = local_13c + 1) {
            local_13d = (int) local_12c ^ (int) local_128[local_13c];
            char p = local_13d;
            printf("%c", p);
            strncat(&local_79,(char *)&local_13d,1);
        }
    printf("%c", local_79);
}
