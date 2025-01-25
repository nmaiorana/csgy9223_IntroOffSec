#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

void replace_nl(char* buf) {
    char* nl = strchr(buf, '\n');
    if (nl) { *nl = '\0'; }
}

long get_number() {
    char buf[0x10];
    read(0, buf, 0x10);
    replace_nl(buf);
    return strtol(buf, NULL, 10);
}

int main() {
    // set all fds to be newline buffered
    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    char buf[0x10];
    long x, y;
    puts("Give me two numbers that add up to 23!");
    printf(" > ");
    fflush(stdout);
    x = get_number();
    printf(" > ");
    fflush(stdout);
    y = get_number();
    printf("\n%ld + %ld = %ld\n", x, y, x + y);
    if (x + y == 23) {
        puts("Yes, you win!");
    } else {
        printf("Nope, those add to %ld!\n", x + y);
    }
    return 0;
}
