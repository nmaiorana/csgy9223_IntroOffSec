#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

#define BUF_LEN 0x20

int secret_value = 0x13371137;

int main() {
    char buf[BUF_LEN];
    puts("Hi, give me a number!");
    read(0, buf, BUF_LEN);
    int* addr = *(int**)buf;
    puts("Hi, give me another number!");
    read(0, buf, BUF_LEN);
    int val = *(int*)buf;
    *addr = val;
    printf("My secret value is: %x\n", secret_value);
    if (secret_value == 0xdeadbeef) {
        puts("Yes, you win!");
    } else {
        puts("Nope, try the arbitrary write again!");
    }
    return 0;
}
