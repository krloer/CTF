#ifndef FIGHT_H_   /* Include guard */
#define FIGHT_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pokemon.h"


void printAttack(char* name, int64_t  hp, int64_t  damage);
void printDefense(char* name,  int64_t  hp, int64_t  damage, int64_t newhp);
struct Pokemon *fight(struct Pokemon* p1, struct Pokemon *p2);
int64_t  battle(struct Pokemon *pokemon);
    
#endif 