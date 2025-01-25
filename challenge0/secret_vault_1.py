from pwn import *

address_of_vault = 0x0000000000001249
base_address = 0x5563d5647000

print(hex(base_address + address_of_vault))
