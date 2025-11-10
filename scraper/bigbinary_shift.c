//
// Created by Poupi on 10/11/2025.
//

#ifndef PROJET_C_V1_BIGBINARY_SHIFT_H
#define PROJET_C_V1_BIGBINARY_SHIFT_H

#include "bigbinary.h"

// Retourne true si x est pair (à implémenter)
bool isEven(const BigBinary *x) {
    (void)x;
    return false;
}

// Décale x d'un bit vers la droite (x = x / 2 en binaire)
void shiftRight1(BigBinary *x) {
    (void)x;
    // TODO: manipuler le LSB et la taille, puis normalize
}

// Décale x d'un bit vers la gauche (x = x * 2 en binaire)
void shiftLeft1(BigBinary *x) {
    (void)x;
    // TODO: ajouter un bit 0 en LSB
}

// Décale x de k bits vers la gauche
void shiftLeftK(BigBinary *x, int k) {
    (void)x;
    (void)k;
    // TODO: appeler shiftLeft1 k fois (ou faire mieux)
}

// Retire tous les facteurs 2 de x, renvoie combien il y en avait
int stripFactorsOfTwo(BigBinary *x) {
    (void)x;
    // TODO: tant que x est pair, shiftRight1

    return 0;
}


#endif //PROJET_C_V1_BIGBINARY_SHIFT_H
