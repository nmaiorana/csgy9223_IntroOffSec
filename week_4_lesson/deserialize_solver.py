from pwn import *

p = process("./deserialize")
# assemble packet body first, then prepend header values
# need an array that results in a dot product of 0x99
array1 = [0x3, 0x8, 0xa]
array2 = [0x7, 0x4, 0xa]

assert sum(x * y for x, y in zip(array1, array2)) == 0x99

body = p8(len(array1)) + b''.join(map(p8, array1)) + b''.join(map(p8, array2))

# prepend header values
# packet array type
packet = b'\x02' + body
# sequence number
packet  = p32(0xdeadbeef) + packet
# len
packet = p8(len(packet) + 1) + packet

p.send(packet)
p.interactive()