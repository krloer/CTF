#include "pokemon.h"

char* PokemonTypeLookupTable[] = {"Pikachu", "Bulbasaur", "Charmander", "Squirtle","Pidgeotto","Ratata","Grimer","Caterpie","Dratini","Krabby", 
                                "Raichu", "Venusaur", "Charizard", "Blastoise", "Pidgeot", "Raticate", "Muk", "Butterfree", "Dragonite", "Kingler", "Entei"};

double  evolvedAttackMultiplier() {
    return ((double)rand() / (double)RAND_MAX) + 1;
}


double  shadowAttackMultiplier() {
    return ((double)rand() / (double)RAND_MAX) + 1.5;
}

int64_t  evolve(struct Pokemon *pokemon) {
    pokemon->type = pokemon->type+10; 
    pokemon->hp = (rand() % 1000)+1;
    pokemon->cp = (rand() % 10) +1;
    pokemon->evolve = NULL;
    pokemon->multiplier = evolvedAttackMultiplier;
    char* newname = PokemonTypeLookupTable[pokemon->type];
    printf("%s grew stronger! It is now knowns as %s. New HP: %ld, new CP %ld \n",pokemon->name, newname, pokemon->hp, pokemon->cp);
    strcpy(pokemon->name, PokemonTypeLookupTable[pokemon->type]);
    return 1;
}

int64_t  generateShadowPokemon(struct Pokemon *pokemon) {
    pokemon->type = 20; 
    strcpy(pokemon->name, PokemonTypeLookupTable[pokemon->type]);
    pokemon->hp = (rand() % 1337)+1;
    pokemon->cp = (rand() % 13)+1;
    pokemon->evolve = evolve;
    pokemon->multiplier = shadowAttackMultiplier;
    return 1;
}


int64_t  catch_pokemon(struct Pokemon *pokemon ) {
    if ((rand() % 100) > CATCH_PERCENTAGE) {
        return 0;
    }
    pokemon->type = rand()%10; 
    strcpy(pokemon->name, PokemonTypeLookupTable[pokemon->type]);
    pokemon->hp = rand() % 100;
    pokemon->cp = rand() % 100;
    pokemon->evolve = evolve;
    return 1;


}

void viewPokemon(struct Pokemon *pokemon, int64_t  candy, int64_t  idx) {
    printf("| %5ld | %15s | %6ld | %6ld | %6ld | %10s |\n",idx, pokemon->name,pokemon->hp, pokemon->cp, candy, pokemon->evolve ? "True" : "False");
}

