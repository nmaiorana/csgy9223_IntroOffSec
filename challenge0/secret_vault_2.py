from pwn import *
fake_vault_offset = 0x0000000000004029
fake_vault_address = 0x55baab5bf029
base_address = fake_vault_address - fake_vault_offset
secret_vault_offset = 0x0000000000001269
secret_vault_address = base_address + secret_vault_offset
print(hex(secret_vault_address))

