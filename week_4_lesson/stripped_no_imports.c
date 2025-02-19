int mywrite() {
    __asm__ ("movq $1, %rax\n\t"
             "syscall");
}

int main() {
    mywrite(1, "Hello World\n", 12);
    return 0;
}
