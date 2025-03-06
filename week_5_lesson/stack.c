#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

void win() {
	printf("If you make it here, you win!");
    system("/bin/sh");
    exit(0);
}

void greet() {
	char buf[0x20];
    puts("Hi, what's your name??");
    gets(buf);
    printf("Hello, %s\n", buf);
}

int main() {
	greet();
	return 0;
}
