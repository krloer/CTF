#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // srand(time(NULL));
    char key[7] = {14, -68, 29, -113, 41, -94, 107};
    // for (int i = 0; i < sizeof(key); i++)
    // {
    //     key[i] = rand() % 256;
    //     printf("%d ", key[i]);
    // }
    // puts("");
    _Static_assert(sizeof(key) == 7, "Invalid key size!");

    char* real_flag = "flag{abc123def456cba_hello}\0";

    char* flag = malloc(29);
    strncpy(flag, real_flag, 29);

    int flag_len = strlen(flag);
    int key_len = strlen(key);

    for(int i = 0; i < flag_len - key_len + 1; i++) {
        for(int j = 0; j < key_len; j++) {
            flag[i + j] ^= key[j];
        }
    }

    printf("%s", flag);
    free(flag);
    return 0;
}

