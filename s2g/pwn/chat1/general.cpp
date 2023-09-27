#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


#ifndef VULN_1
#define VULN_1 0
#endif

#ifndef VULN_2
#define VULN_2 0
#endif

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 16
#endif

#ifndef USERNAME_SIZE
#define USERNAME_SIZE 32
#endif

// Function to respond to a greeting
void respondToGreeting() {
    printf("Chatbot: Hello! How can I help you today?\n");
}



void printFlag()
{
    FILE *fptr;
    fptr = fopen("flag.txt", "r");
    char flag[100];
    if (! fptr)
    {
        puts("flag file not found!\n");
        exit(0);
    }
    fgets(flag, 100, fptr);
    printf("%s\n", flag);
    fclose(fptr);
    exit(0);
}

#if VULN_1

void respondToGuess()
{
    char secret[] = "blue";
    char name[BUFFER_SIZE] = {0};
    printf("Chatbot: Can you guess the secret?\n");
    printf("Chatbot: Please enter your favorite color:\n");
    scanf("%s", name);
    fflush(stdin);

    if (strcmp(secret, "pink")==0)
    {
        puts("Chatbot: Wow! Here's a secret.\n");
        printFlag();
    }
    else
    {
        printf("Chatbot: I guess you're not cool enough to see my secret\n");
        //printf(" \'%s\'.\n", secret);
    }
}

#else

void respondToGuess()
{
    printf("Chatbot: Can you guess the secret?\n");
    printf("Chatbot: Please enter your favorite color:\n");
    char name[BUFFER_SIZE] = {0};
    char secret[] = "blue";
    fflush(stdin);
    fgets(name, BUFFER_SIZE, stdin);

    if (secret == "pink")
    {
        puts("Chatbot: Wow! Here's a secret.\n");
        printFlag();
    }
    else
    {
        printf("Chatbot: I guess you're not cool enough to see my secret\n");
        //printf(" \'%s\'.", secret);
    }
}
#endif


#if VULN_2
bool GetName(char *userName){
    char tempName[USERNAME_SIZE];
    printf("Chatbot: Please enter your name to get started\n");
    printf("Chatbot: Username address: %p\n", userName);
    scanf("%s", tempName);
    fflush(stdin);
    strncpy(userName, tempName, USERNAME_SIZE);
    return 1;
}
#else

bool GetName(char *userName){
    char tempName[USERNAME_SIZE];
    printf("Chatbot: Please enter your name to get started\n");
    printf("Chatbot: Username address: %p\n", userName);
    fgets(tempName, USERNAME_SIZE, stdin);
    fflush(stdin);
    strtok(tempName, "\n");
    strncpy(userName, tempName, USERNAME_SIZE);
    return 1;
}
#endif

// Function to respond to a farewell
void respondToFarewell() {
    printf("Chatbot: Goodbye! Have a great day!\n");
}


int main() {

    //printf("VULN_1 = %d, VULN_2 = %d, BUFFER_SIZE = %d, userName = %d\n", VULN_1, VULN_2, BUFFER_SIZE, USERNAME_SIZE);
    char userMessage[100];
    char userName[USERNAME_SIZE];
    if (! GetName(userName))
    {
        printf("Chatbot: Errr..User is a hacker!");
        printFlag();
    }
    else
    {
        printf("Chatbot: Hi %s! How can I assist you today?\n", userName);
    }

    while (1) {
        printf("\n\nYou: ");
        fflush(stdin);
        fgets(userMessage, 100, stdin);

        if (strstr(userMessage, "hello") || strstr(userMessage, "hi")) {
            respondToGreeting();
        } else if (strstr(userMessage, "guess")) {
            respondToGuess();
        } else if (strstr(userMessage, "bye") || strstr(userMessage, "goodbye")) {
            respondToFarewell();
            break;
        } else {
            printf("\nChatbot: I'm not sure how to respond to that.\n");
        }
    }

    return 0;
}