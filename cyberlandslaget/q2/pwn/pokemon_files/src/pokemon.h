#ifndef POKEMON_H_  
#define POKEMON_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#define CATCH_PERCENTAGE 50


typedef enum {Pikachu, Bulbasaur, Charmander, Squirtle, Pidgeotto,Ratata,Grimer,Caterpie,Dratini,Krabby,
              Raichu,  Venusaur,  Charizard,  Blastoise,Pidgeot,Raticate, Muk, Butterfree,Dragonite,Kingler, Entei } PokemonType;


struct Pokemon {
    char name[16];
    PokemonType type;
    int64_t  (*evolve)();
    double (*multiplier)();
    int64_t  hp;
    int64_t  cp;
};

int64_t  catch_pokemon(struct Pokemon *pokemon );
void viewPokemon(struct Pokemon *pokemon, int64_t  candy, int64_t  idx);
int64_t  generateShadowPokemon(struct Pokemon *pokemon);
int64_t  evolve(struct Pokemon *pokemon);
double shadowAttackMultiplier();
double  evolvedAttackMultiplier();

#endif 