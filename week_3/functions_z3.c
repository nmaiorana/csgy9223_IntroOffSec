#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "stdbool.h"

int get_int() {
    char buf[0x10];
    fgets(buf, 0x10, stdin);
    char* nl = strchr(buf, '\n');
    if (nl) { *nl = '\0'; }
    return atoi(buf);
}

int perform_mod(int a, int b) {
    return a % b;
}

bool check(int x, int y, int z) {
    if (x * y != -1508619901) { return false; }
    if (perform_mod(z, 73) != 28) { return false; }
    if (y / z != 9 || y + z != 53798) { return false; }
    return true;
}

bool check_bounds(int x, int y, int z) {
    if (x < 0 || y < 0 || z < 0) { return false; }
    if (x > 0x10000 || y > 0x10000 || z > 0x10000) { return false; }
    return true;
}

int main() {
    int x, y, z;
    puts("Give me the three secret numbers: ");
    x = get_int();
    y = get_int();
    z = get_int();
    if (!check_bounds(x, y, z)) { goto fail; }
    if (!check(x, y, z)) { goto fail; }
    puts("Those are the correct answers!");
    puts("You win!!");
    return 0;
fail:
    puts("Nope! Those numbers are not correct!!");
    return 1;
}
