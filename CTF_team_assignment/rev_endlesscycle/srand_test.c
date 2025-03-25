#include <stdio.h>
#include <stdlib.h>

int main() {
    // Seed the random number generator
    srand(3486694491);

    // Generate and print the first 8 random values
    for (int i = 0; i < 8; i++) {
        printf("%d\n", rand());
    }

    return 0;
}