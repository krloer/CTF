

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#define INPUT_NUM_SIZE 10
#define MAX_ITEMS 12
#define CHUNK_SIZE 0x50
void* itemList[MAX_ITEMS];

void ignore_me_init_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig) {
    if (sig == SIGALRM) {
        printf("[!] Anti DoS Signal. Patch me out for testing.");
        exit(0);
    }
}

void ignore_me_init_signal() {
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}


void print_menu( void ) {
    printf("\n##### MENU ####\n");
    printf("1. Create \n");
    printf("2. Edit.\n");
    printf("3. View.\n");
    printf("4. Delete.\n");
    printf("5. Exit.\n");
    printf("> ");
}

void  winner( void ) {
    system("/bin/sh");
} 

int read_int_input(char* prompt) {
    if (prompt) {
        printf("%s", prompt);
    }
    char buffer[INPUT_NUM_SIZE];
    fgets(buffer, INPUT_NUM_SIZE, stdin);
    return atoi(buffer);
}

void create( void ) {
    int idx  = read_int_input("Index?\n> ");
    if (idx < 0 || idx >= MAX_ITEMS) {
        puts("[!] Index out of range.");
        exit(1337);
    }
    itemList[idx] = malloc(CHUNK_SIZE);
}

void edit( void ) {
    char buffer [CHUNK_SIZE+1] ;
    int idx  = read_int_input("Index?\n> ");
    if (idx < 0 || idx >= MAX_ITEMS) {
        puts("[!] Index out of range.");
        exit(1337);
    }
    if (itemList[idx] == NULL) {
        puts("[-] Cant edit nullptr.");
        return;
    }
    printf("Data > ");
    fgets(buffer, CHUNK_SIZE, stdin);
    strtok(buffer, "\n");
    strcpy(itemList[idx], buffer);
}

void delete ( void ) {
    int idx  = read_int_input("Index?\n> ");
    if (idx < 0 || idx >= MAX_ITEMS) {
        puts("[!] Index out of range.");
        exit(1337);
    }
    if (itemList[idx] == NULL) {
        puts("[-] Cant free nullptr.");
        return;
    }
    free(itemList[idx]);
}

void view( void ) {
    int idx  = read_int_input("Index?\n> ");
    if (idx < 0 || idx >= MAX_ITEMS) {
        puts("[!] Index out of range.");
        exit(1337);
    }
    if (itemList[idx] == NULL) {
        puts("[-] Cant view nullptr.");
        return;
    }
    puts(itemList[idx]);
}

int main() {
    int choice;
    ignore_me_init_buffering();
    ignore_me_init_signal();
    do {
        print_menu();
        choice = read_int_input(NULL);

        switch (choice) {
            case 1:
                create();
                break;
            case 2:
                edit();
                break;
            case 3:
                view();
                break;
            case 4:
                delete();
                break;
            case 5:
                break;
            default:
                printf("Invalid choice.\n");
        }
    } while (choice != 5);

    return 0;
}