#include "fight.h"

void printAttack(char* name, int64_t  hp, int64_t  damage) {
    printf("%s [%ld hp] attacks for %ld damage\n", name, hp, damage);
}

void printDefense(char* name,  int64_t  hp, int64_t  damage, int64_t newhp) {
    printf("%s [%ld hp] got hit for %ld damage. New hp %ld\n", name, hp, damage, newhp);
}

struct Pokemon *fight(struct Pokemon* p1, struct Pokemon *p2) {
    int64_t  newHp;
    while (p1->hp > 0 && p2->hp > 0) {
        // p1 attacks p2

        printAttack(p1->name,p1->hp,  p1->cp);
        newHp = p2->hp - p1->cp;
        printDefense(p2->name, p2->hp, p1->cp, newHp );
        p2->hp = newHp;
        if (p2->hp <= 0) {
            return p1;
        }
        // p2 attacks p1
        printAttack(p2->name,p2->hp,  p2->cp);
        newHp = p1->hp - p2->cp;
        printDefense(p1->name, p1->hp, p2->cp, newHp );
        p1->hp = newHp;
        
    }
    return p2->hp <= 0 ? p1 : p2;
}


int64_t  battle(struct Pokemon *pokemon){
    char status[0x90] = "%s won the fight, and has %d hp left.\n";
    pokemon->cp = pokemon->multiplier() * pokemon->cp;
    
    struct Pokemon shadowPokemon;
    generateShadowPokemon(&shadowPokemon);
    shadowPokemon.cp = shadowPokemon.multiplier() * shadowPokemon.cp;
    struct Pokemon* winner = fight(pokemon, &shadowPokemon);
     printf(status, winner->name, winner->hp);
    if (winner == pokemon) 
        return 1;
    return 0;
}

