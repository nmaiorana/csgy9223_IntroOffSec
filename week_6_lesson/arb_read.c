#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

#define BUF_LEN 0x20

int secret_value = 0x13371137;

int main() {
    char buf[BUF_LEN];
    puts("Hi, give me a number!");
    read(0, buf, BUF_LEN);
    printf("%llx\n", **(unsigned long long**)buf);
    return 0;
}
