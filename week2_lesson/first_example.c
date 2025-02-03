// first_example.c
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

int main() {
    char buf[0x10];
    printf("> ");
    fgets(buf, sizeof(buf), stdin);
    char start = (char)atoi(buf);
    char i = start;

    while (1) {
        if (i == start + 10) {
	        puts("\n");
	        return 0;
	    }
        char c = (i + 'A'); // adding a char to a char
        // performing a char to char comparison
        if (c > 'z' || (c < 'a' && c > 'Z')) {
            puts("\n");
            return 1;
        }
        if (i % 2 == 0) { // performing a mathematical operation on a char
	        printf("%x ", c);
	    }
        else {
	        printf("%c ", c);
	    }
        i += 1; // performing a mathmatical operation on a char
    }
    puts("\n");
    return 0;
}
