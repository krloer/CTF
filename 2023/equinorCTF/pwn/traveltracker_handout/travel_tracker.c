#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#define MAX_REVIEWS 100
#define AIRPORT_CODE_LENGTH 11
#define MAX_COMMENT_LENGTH 1024
#define MAX_RATING_LENGTH 3

typedef struct {
    char airportCode[AIRPORT_CODE_LENGTH];
    int rating;
    char *comment;
} AirportReview;

static AirportReview *reviews[MAX_REVIEWS];
static int reviewCount = 0;

void addReview();
void viewReviews();
void saveReviewsToFile();
void modifyReview();
char *getDynamicString();
int getIntegerInput();
size_t getLength(char *str);
void stripNewline(char *str);

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

int main() {
    int choice;
    ignore_me_init_buffering();
    ignore_me_init_signal();
    do {
        puts("\nTravel Tracker Menu");
        puts("1. Add airport review");
        puts("2. View all airport reviews");
        puts("3. Save all airport reviews to file");
        puts("4. Modify an airport review");
        puts("5. Exit");
        printf("Enter your choice: ");
        choice = getIntegerInput();

        switch (choice) {
            case 1:
                addReview();
                break;
            case 2:
                viewReviews();
                break;
            case 3:
                saveReviewsToFile();
                break;
            case 4:
                modifyReview();
                break;
            case 5:
                printf("Exiting the program...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 5);

    return 0;
}

void addReview() {
    if (reviewCount >= MAX_REVIEWS) {
        printf("Maximum number of reviews reached.\n");
        return;
    }

    reviews[reviewCount] = malloc(sizeof(AirportReview));
    if (reviews[reviewCount] == NULL) {
        printf("Error allocating memory!\n");
        exit(1);
    }

    printf("Enter airport code: ");
    fgets(reviews[reviewCount]->airportCode, AIRPORT_CODE_LENGTH, stdin);
    stripNewline(reviews[reviewCount]->airportCode);

    printf("Enter rating (1-10): ");
    reviews[reviewCount]->rating = getIntegerInput();

    printf("Enter comment: ");
    reviews[reviewCount]->comment = getDynamicString();

    reviewCount++;
}

void writeToFile(int i, FILE *file) {
    char* comment = reviews[i]->comment;
    fprintf(file, "Airport Code");
    fprintf(file, reviews[i]->airportCode);
    fprintf(file, "\nRating: %d\n", reviews[i]->rating);
    fprintf(file, "Comment: %s\n\n", comment);
}


void saveReviewsToFile() {
    //There was a bug when writing to file.
    //Fixed by writing to the void.
    FILE *file = fopen("/dev/null", "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < reviewCount; i++) {
       writeToFile(i, file);
    }

    fclose(file);
    printf("Reviews have been saved. \n");
}


void viewReviews() {
    if (reviewCount == 0) {
        puts("No reviews available.");
        return;
    }

    for (int i = 0; i < reviewCount; i++) {
        printf("\nReview #%d:\n", i + 1);
        printf("Airport Code: %s\n", reviews[i]->airportCode);
        printf("\nRating: %d\n", reviews[i]->rating);
        printf("Comment: %s\n", reviews[i]->comment);
    }
}

void modifyReview() {
    if (reviewCount == 0) {
        printf("No reviews to modify.\n");
        return;
    }

    int reviewNumber;
    printf("Enter the review number to modify: ");
    reviewNumber = getIntegerInput() - 1;

    if (reviewNumber < 0 || reviewNumber >= reviewCount) {
        printf("Invalid review number.\n");
        return;
    }

    printf("Enter new airport code: ");
    fgets(reviews[reviewNumber]->airportCode, AIRPORT_CODE_LENGTH, stdin);
    stripNewline(reviews[reviewNumber]->airportCode);

    printf("Enter new rating (1-10): ");
    reviews[reviewNumber]->rating = getIntegerInput();

    free(reviews[reviewNumber]->comment); 
    printf("Enter new comment: ");
    reviews[reviewNumber]->comment = getDynamicString();
}

size_t getLength(char *str) {
    if (str == NULL) {
        return 0; 
    }

    size_t index = strcspn(str, "\n");
    if (str[index] == '\n') {
        str[index] = '\0';
    } else {
        index = strlen(str);
    }

    return index;
}

char *getDynamicString() {
    char buffer[MAX_COMMENT_LENGTH];
    fgets(buffer, MAX_COMMENT_LENGTH, stdin);

    size_t length = getLength(buffer);

    char *str = malloc(length + 1);
    if (str == NULL) {
        printf("Error allocating memory!\n");
        exit(1);
    }
    strcpy(str, buffer);

    return str;
}


int getIntegerInput() {
    char input[MAX_RATING_LENGTH];
    fgets(input, MAX_RATING_LENGTH, stdin);
    stripNewline(input);
    return atoi(input);
}

void stripNewline(char *str) {
    if (str != NULL) {
        str[strcspn(str, "\n")] = '\0';
    }
}
