#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

short note_id;
unsigned short note_length;

int main() {
    scanf("%u",&note_id);
    // scanf("%u",&note_length);
    printf("note_id= %hd, note_length = %hu,\n", note_id, note_length);

    return 0;
}   