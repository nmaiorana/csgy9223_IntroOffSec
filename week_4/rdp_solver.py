from pwn import *

context.log_level = "info"

LOCAL = False

if LOCAL:
    p = process("./rdp")
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1272)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")

print(p.recvuntil(b" flag!\n").decode())
message = [0]
opcode = 0

# Send the first packet to establish the connection
packet = p8(len(message) + 2) + p8(opcode) + b''.join(map(p8, message))
p.send(packet)
print(p.recvuntil(b"Connection Established!\n").decode())

# Send the second packet to send the message [55]
message = [0, 55]
opcode = 1

packet = p8(len(message) + 2) + p8(opcode) + b''.join(map(p8, message))
p.send(packet)

print(p.recvuntil(b"That's a nice message!\n").decode())

# Send the third packet to close the connection and get the flag
message = [0]
opcode = 2

packet = p8(len(message) + 2) + p8(opcode) + b''.join(map(p8, message))
p.send(packet)
print(p.recvuntil(b"Disconnected!\n").decode())
print(p.interactive().decode())
