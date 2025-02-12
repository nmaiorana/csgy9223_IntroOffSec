#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "string.h"

int get_int() {
    char buf[0x10];
    fgets(buf, 0x10, stdin);
    char* nl = strchr(buf, '\n');
    if (nl) { *nl = '\0'; }
    return atoi(buf);
}

int main() {
    int x, y, z;
    puts("Give me the three secret numbers: ");
    x = get_int();
    y = get_int();
    z = get_int();
    if (x < 2 || y < 2 || z < 2) { goto fail; }
    if (x > 0x100 || y > 0x100 || z > 0x100) { goto fail; }
    if (x > y || y > z) { goto fail; }
    if (x * y * z != 778910) { goto fail; }
    if (z % x != 37) { goto fail; }
    puts("Those are the correct answers!");
    puts("You win!!");
    return 0;
fail:
    puts("Nope! Those numbers are not correct!!");
    return 1;
}
