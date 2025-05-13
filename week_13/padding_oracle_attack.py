import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = os.urandom(16)  # Random AES key
IV = os.urandom(16)   # Initialization vector

def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def decrypt(ciphertext):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    try:
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:  # Padding error indicates incorrect padding
        return None  # The Oracle leaks failure

def padding_oracle_attack(ciphertext, block_size=16):
    recovered_plaintext = bytearray(block_size)
    intermediate_bytes = bytearray(block_size)

    for byte_index in range(block_size - 1, -1, -1):
        for guess in range(256):
            modified_block = bytearray(ciphertext[-block_size:])  # Last block

            # Modify the padding bytes
            for i in range(byte_index + 1, block_size):
                modified_block[i] ^= intermediate_bytes[i] ^ (byte_index + 1)

            # Modify the current byte being guessed
            modified_block[byte_index] ^= guess

            crafted_ciphertext = ciphertext[:-block_size] + bytes(modified_block)

            # Simulate an oracle response
            if decrypt(crafted_ciphertext) is not None:
                intermediate_bytes[byte_index] = guess ^ (byte_index + 1)
                recovered_plaintext[byte_index] = intermediate_bytes[byte_index] ^ ciphertext[-block_size + byte_index]
                break

    return bytes(recovered_plaintext)

# Example Usage
ciphertext = encrypt(b"SecretMessage!")
print("Recovered:", padding_oracle_attack(ciphertext).decode('utf-8'))