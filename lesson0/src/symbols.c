#include "stdlib.h"
#include "stdio.h"
#include "string.h"

// compile with `gcc symbols.c -o symbols`

const char HELLO[6] = "Hello\0";

int main() {
    char buf[0x10];
    printf("What is your name?\n> ");
    fgets(buf, sizeof(buf), stdin);
    char* newline = strchr(buf, (int)'\n');
    if (newline) { *newline = '\0'; }
    printf("%s %s, your name is %ld letters long\n", HELLO, buf, strlen(buf));
    puts("Goodbye!");
    return 0;
}
