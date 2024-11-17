#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h> 
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define MAX_ITEMS 10
#define PIN_LENGTH 12
#define MAX_ITEM_LENGTH 30
char vaultItems[MAX_ITEMS][50];
int itemCount = 0;

void ignore_me_init_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void kill_on_timeout(int sig) {
    if (sig == SIGALRM) {
        printf("[!] Anti DoS Signal. Patch me out for testing.");
        _exit(0);
    }
}

void ignore_me_init_signal() {
    signal(SIGALRM, kill_on_timeout);
    alarm(60);
}


void setPIN(char* pin) {

    FILE *fp;
    unsigned char bytes[5];
    fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        perror("Error opening /dev/urandom");
        exit(1);
    }
    if (fread(bytes, 1, 5, fp) != 5) {
        perror("Error reading from /dev/urandom");
        fclose(fp);
        exit(1);
    }
    fclose(fp);
    for (int i = 0; i < 5; i++) {
        sprintf(&pin[i * 2], "%02x", bytes[i]);
    }

    pin[10] = '\0'; // Null terminate the string

    return;
}

bool checkPIN(char * pin) {

    char enteredPIN[PIN_LENGTH];
    printf("Enter your PIN to access the vault: ");
    fgets(enteredPIN, PIN_LENGTH, stdin);
    enteredPIN[strcspn(enteredPIN, "\n")] = '\0';  

    if (strcmp(pin, enteredPIN) == 0) {
        return true;
    }
    char output[100];
    sprintf(output, "the pin %s is not correct",enteredPIN );
    printf(output);
    return false;
}

void addItem() {
    if (itemCount >= MAX_ITEMS) {
        printf("Vault is full. Cannot add more items.\n");
        return;
    }

    printf("Enter item to add to the vault: ");
    fgets(vaultItems[itemCount], MAX_ITEM_LENGTH, stdin);
    vaultItems[itemCount][strcspn(vaultItems[itemCount], "\n")] = '\0'; 
    itemCount++;
    printf("Item added successfully.\n");
}

void removeItem() {
    if (itemCount == 0) {
        printf("Vault is empty. No items to remove.\n");
        return;
    }

    itemCount--;
    printf("Last item removed successfully.\n");
}

void listItems() {
    if (itemCount == 0) {
        printf("Vault is empty.\n");
        return;
    }

    printf("Items in the vault:\n");
    for (int i = 0; i < itemCount; i++) {
        printf("%d. %s\n", i + 1, vaultItems[i]);
    }
}

void readFlag( void ) {
    FILE *file = fopen("/opt/flag", "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(1);
    }
    char flag[50];
    if (fgets(flag, 50, file) == NULL) {
        perror("Error reading flag from file");
        fclose(file);
        exit(1);
    }

    printf("gj! the flag is %s", flag);
    fclose(file);
}

int main( void ) {
    char input[10]; 
    char pin[PIN_LENGTH];
    int choice;
    bool accessGranted = false;
    ignore_me_init_buffering();
    ignore_me_init_signal();
    setPIN(pin);

    do {
        printf("\n--- Vault Menu ---\n");
        printf("1. Open Vault\n2. Add Item\n3. Remove Item\n4. List Items\n5. Read flag\n6. Exit\n");
        printf("Enter your choice: ");
        fgets(input, 10, stdin); 

        choice = atoi(input); 

        switch (choice) {
            case 1:
                accessGranted = checkPIN(pin);
                if (accessGranted) {
                    printf("Vault opened successfully.\n");
                } 
                break;
            case 2:
                if (accessGranted) addItem();
                else printf("Please open the vault first.\n");
                break;
            case 3:
                if (accessGranted) removeItem();
                else printf("Please open the vault first.\n");
                break;
            case 4:
                if (accessGranted) listItems();
                else printf("Please open the vault first.\n");
                break;
            case 5:
                if (accessGranted) readFlag();
                else printf("Please open the vault first.\n");
                break;
            case 6:
                printf("Exiting program.\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 6);

    return 0;
}