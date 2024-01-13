#include <stdio.h>
#include <string.h>

size_t hash_string(char *string) {
    size_t hash = 0;
    size_t len = strlen(string);
    if (len > 16)
        return 0;

    for (size_t i = 0; i < len; i++) {
        hash += string[i] * 31;
    }
    return hash;
}

void increment(char *key) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;
    printf("%ld\n",hash);

    size_t index = hash % 10;
    printf("%ld",index);
}

int main() {
	char name_input[16] = {0};
	fgets(name_input, sizeof(name_input), stdin);
	increment(name_input);
}
