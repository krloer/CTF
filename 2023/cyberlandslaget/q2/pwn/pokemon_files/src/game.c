#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "pokemon.h"
#include "fight.h"


#define POKEDEX_SIZE 4
#define CANDY_TO_EVOLVE 0
extern char* PokemonTypeLookupTable[];
struct Trainer {
    char name[20];
    struct Pokemon *pokedex[POKEDEX_SIZE];
    int64_t  candyList[10];
    int64_t  numberOfPokemons;
} trainer;

int isValidAscii(const char* str) {
    if (!islower(str[0]) && !isupper(str[0])) {
        return 0;
    } 
    for (int i = 1; str[i] != '\0'; i++) {
        if (!islower(str[i])) {
            return 0;
        }
    }
    return 1;
}

void seedRand(void) {
    uint64_t seed;
    int64_t  fd;
    if ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
        fprintf(stderr, "Error opening urandom for reading.");
        exit(1);
    }
    if((read(fd,(uint64_t*)&seed,sizeof(seed))) < 0){
         fprintf(stderr, "Error reading from urandom.");
        exit(1);
    }
    close(fd);
    srand(seed);
}

void init_buffering(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void read_string(char *input_buffer, size_t buffer_size, const char *prompt) {
    printf("%s", prompt);
    fgets(input_buffer, buffer_size, stdin);
    input_buffer[strcspn(input_buffer, "\n")] = '\0'; 
}

int64_t  read_integer(const char *prompt) {
    char input_buffer[256];
    int64_t  value;
    memset(input_buffer, '\0', sizeof(input_buffer));
    printf("%s", prompt);
    fgets(input_buffer, sizeof(input_buffer), stdin);
    input_buffer[strcspn(input_buffer, "\n")] = '\0'; 

    if (sscanf(input_buffer, "%ld", &value) != 1) {
        fprintf(stderr, "Error: Invalid input - could not read integer.\n");
        exit(EXIT_FAILURE);
    }

    return value;
}

int64_t  ask_yes_no_question(char* question) {
    char answer[4];
    while (1) {
        printf("%s (y/n): ", question);
        fgets(answer, 4, stdin);
        fflush(stdin);
        if (strlen(answer) != 2 || (answer[0] != 'y' && answer[0] != 'n' && answer[0] != 'Y' && answer[0] != 'N')) {
            printf("Invalid input. Please answer y/n.\n");
        } else {
            break;
        }
    }
    if (answer[0] == 'y' || answer[0] == 'Y') {
        return 1; 
    } else {
        return 0; 
    }
}

void printMenu( void ) {
    puts("");
    puts("1. View pokedex");
    puts("2. Catch pokemon");
    puts("3. Transfer pokemon to Professor Willow");
    puts("4. Evolve pokemon");
    puts("5. Battle Team Rocket Grunt!");
    puts("6. Exit");
}

void catch() {
    struct Pokemon pokemon;
    int64_t  idx;
    if (!catch_pokemon(&pokemon)) {
        puts("the pokemon fled!");
        return;
    }
    for (idx = 0; trainer.pokedex[idx] != NULL && idx < POKEDEX_SIZE; idx++);

    char str[100];
    sprintf(str, "You just caught a %s with %ld hp and %ld cp. Want yo keep it?", pokemon.name, pokemon.hp, pokemon.cp);
    if(ask_yes_no_question(str)) {
        trainer.pokedex[idx] = malloc(sizeof(struct Pokemon));
        memcpy(trainer.pokedex[idx], &pokemon, sizeof(struct Pokemon));    
    }
    else {
        trainer.candyList[pokemon.type] += 3;
        printf("%s was transfered to teh professor. You got 3 candy. \n", pokemon.name);
    }
}

void startBattle( void ){
    int64_t  idx = read_integer("Select your pokemon (index):\n> ");
    if (idx >= 0 && idx < POKEDEX_SIZE && trainer.pokedex[idx] != NULL && trainer.pokedex[idx]->multiplier != NULL) {
        if (!battle(trainer.pokedex[idx])) {
            printf("%s lost and is transfered from your pokedex.\n", trainer.pokedex[idx]->name);
            if (idx >= 0 && idx < POKEDEX_SIZE && trainer.pokedex[idx] != NULL && trainer.pokedex[idx] != NULL) {
                free(trainer.pokedex[idx]);
                trainer.pokedex[idx] = NULL;
            }
        } else {
            puts("You won, congratulations!!");
        }
    }
    else{
        printf("%s is not strong enough to battle.", trainer.pokedex[idx]->name);
    }
}

void viewPokedex( void ){ 
    printf("-------------------------------------------------------------------\n");
    printf("| %5s | %15s | %6s | %6s | %6s | %10s |\n", "INDEX", "TYPE", "HP", "CP", "CANDY", "CAN EVOLVE");
    printf("-------------------------------------------------------------------\n");
    for (int64_t  i = 0; i < POKEDEX_SIZE; i++) {
        if (trainer.pokedex[i] != NULL && trainer.pokedex[i] != NULL) {
            viewPokemon(trainer.pokedex[i], trainer.candyList[trainer.pokedex[i]->type], i);
        }
    }
    printf("-------------------------------------------------------------------\n");
}

void transfer( void) {
    int64_t  idx = read_integer("Enter pokedex index to transfer:\n> ");
    if (idx >= 0 && idx < POKEDEX_SIZE && trainer.pokedex[idx] != NULL && trainer.pokedex[idx] != NULL) {
        trainer.candyList[trainer.pokedex[idx]->type] += 3;
        free(trainer.pokedex[idx]);
        trainer.pokedex[idx] = NULL;
    }
    else {
        puts("Invalid index!");
    }
}

void evolveIt( void ) {
    int64_t  idx = read_integer("Enter pokedex index to evolve:\n> ");
    if (idx >= 0 && idx < POKEDEX_SIZE && trainer.pokedex[idx] != NULL && trainer.pokedex[idx]->evolve != NULL) {
        if (trainer.candyList[trainer.pokedex[idx]->type] >= CANDY_TO_EVOLVE) {
            trainer.candyList[trainer.pokedex[idx]->type] -= CANDY_TO_EVOLVE;
            trainer.pokedex[idx]->evolve(trainer.pokedex[idx]);
        }
        else{
            puts("not enough candy to evolve.");
        }
    }
}

int  main(int  argc, char *argv[]) {
    seedRand();
    init_buffering();
    trainer.numberOfPokemons =0;
    read_string(trainer.name, sizeof(trainer.name), "Enter your name: ");
    if (!isValidAscii(trainer.name)){
        puts("that is not a valid name!");
        exit(1);
    }
     while(1) {
        printMenu();
        uint32_t num = read_integer("> ");
        switch(num) {
            case 1:
                viewPokedex();
                break;
            case 2: 
               catch();
                break;
            case 3: 
                transfer();
                break;
            case 4: 
                evolveIt();
                break;
            case 5: 
                startBattle();
                break;
            case 6: 
                exit(1);
            default:
                puts("out of range.");
                break;       
        }
    }
}