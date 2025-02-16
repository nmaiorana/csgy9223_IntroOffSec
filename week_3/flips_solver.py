from pwn import *

context.log_level = "info"


def generate_value_with_n_bits(n):
    return (1 << n) - 1


node_order = [3, 1, 4, 0, 5, 2, 7, 9, 6, 8]
node_values = [0xe, 0xd, 0x13, 0x12, 0x11, 0x12, 0x14, 0xe, 0xf, 0x13]

LOCAL = False

if LOCAL:
    p = process("./flips")
else:
    p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1262)
    p.recvuntil(b"abc123):")
    p.sendline(b"nam10102")
    libc = "./basic_math"

for node_numer, node_value in zip(node_order, node_values):
    print(p.recvuntil(b"Tell me two numbers?").decode())
    print(p.recvuntil(b"> ").decode())
    print(node_numer)
    condition_test = generate_value_with_n_bits(node_value)
    num1 = 0x12
    num2 = condition_test ^ num1
    p.sendline(str(num1))
    print(p.recvuntil(b"> ").decode())
    p.sendline(str(num2))

# Reap the rewards
print(p.interactive().decode())
