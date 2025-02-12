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
    if (x < 0 || y < 0 || z < 0) { goto fail; }
    if (x > 0x10000 || y > 0x10000 || z > 0x10000) { goto fail; }
    if (x * y != -1508619901) { goto fail; }
    if (z % 73 != 28) { goto fail; }
    if (y / z != 9 || y + z != 53798) { goto fail; }
    puts("Those are the correct answers!");
    puts("You win!!");
    return 0;
fail:
    puts("Nope! Those numbers are not correct!!");
    return 1;
}
