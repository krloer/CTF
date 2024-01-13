#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

short note_id;
unsigned short note_length;
char note[100];
char note_overflow[100];

int main() {
    while (1) {
        unsigned short char_count_inp;
        short old_note_id;
        long canary;
        
        char_count_inp = 0;
        old_note_id = note_id;

        printf("Start: note_id= %hd, note_length = %hu,\n", note_id, note_length);

        puts("Note ID:");
        scanf("%u",&note_id);
        if (old_note_id == note_id) {
            puts("Old note ID, using old length");
        }
        else {
            puts("Note length: [MAX 99 CHARACTERS]");
            scanf("%u",&char_count_inp);
            if (99 < char_count_inp) {
                puts("Note length too long try again");
                return 0;
            }
        note_length = char_count_inp;
        }
        puts("Message:");
        read(0, &note,(unsigned long) note_length);

        printf("note_id= %hd, note_length = %hu\n", note_id, note_length);
        printf("note = %s\n", note);
        printf("shellcode = %s\n\n", note_overflow);
        getchar();
    }

    return 0;
}   