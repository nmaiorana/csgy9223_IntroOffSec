from pwn import *
import binascii

context.log_level = "info"
good_padding_message = b"That's a valid message :)"
bad_padding_message = b"Oh no, bad padding :("


def split_into_blocks(data, block_size):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def get_blocks(block_index, ciphertext_blocks, iv):
    current_block = ciphertext_blocks[block_index]
    if block_index == 0:
        previous_block = iv
    else:
        previous_block = ciphertext_blocks[block_index - 1]
    return current_block, previous_block


def init_state(block_size):
    state = bytearray(block_size)
    return state


def init_modified_block(byte_index, padding_value, previous_block, state):
    # Modify the current block to test padding
    block_size = len(previous_block)

    modified_block = bytearray(b'\xff' * block_size)
    for i in range(block_size - 1, byte_index, -1):
        print(f"Modifying byte {i} to {hex(state[i] ^ padding_value ^ previous_block[i])}")
        modified_block[i] = padding_value ^ previous_block[i] ^ state[i]
    decrypted_padding = bytearray(b1 ^ b2 ^ b3 for b1, b2, b3 in zip(modified_block, previous_block, state))
    print(f"Decrypted padding block: {binascii.hexlify(decrypted_padding)}")
    return modified_block


def find_state(p, block_index: int, byte_index: int, iv: bytearray, ciphertext_blocks: list, state: bytearray,
               padding_value: int):
    block_size = len(iv)
    # Modify the current block to test padding
    if block_index == 0:
        previous_block = iv
        prior_blocks = []
    else:
        previous_block = ciphertext_blocks[block_index - 1]
        prior_blocks = ciphertext_blocks[0:block_index]

    modified_block = init_modified_block(byte_index, padding_value, previous_block, state)
    print(f"Prior blocks: {binascii.hexlify(b"".join(prior_blocks))}")
    print(f"Looking for padding {padding_value} for byte index {byte_index}")
    print(f"Previous block: {binascii.hexlify(previous_block)}")
    print(f"Current block : {binascii.hexlify(ciphertext_blocks[block_index])}")
    print(f"Modified block: {binascii.hexlify(modified_block)}")
    print(f"Current state : {binascii.hexlify(state)}")

    send_iv = binascii.hexlify(bytes(iv))
    send_ciphertext = binascii.hexlify(bytes(b"".join(prior_blocks) + modified_block))
    payload = send_iv + send_ciphertext
    print(f"Core Payload: {payload}")

    for guess in range(256):
        modified_block[byte_index] = guess

        send_ciphertext = binascii.hexlify(bytes(b"".join(prior_blocks) + modified_block))
        payload = send_iv + send_ciphertext

        p.sendline(payload)
        # print(f"Sent data: {payload}")
        res = p.readline().strip()
        # print(f"Response: {res} for block {0} byte {byte_index} guess {guess}")
        p.recvuntil(b"Send me a message!\n")
        if good_padding_message in res:
            print(f"Sent data: {payload}")
            print(
                f"Guess {hex(guess)} previous block: {hex(previous_block[byte_index])} for padding {hex(padding_value)}")
            state[byte_index] = compute_state(byte_index, guess, padding_value, previous_block)
            return
        elif bad_padding_message not in res:
            print(f"Sent data: {payload}")
            print(f"Unexpected response: {res}")
            # Handle unexpected response
            # You can choose to raise an exception or log the error
            # For now, we'll just print it and continue
            print(f"Unexpected response: {res}")
            p.recvuntil(b"Send me a message!\n")
            assert False

    assert False


def compute_state(byte_index, guess, padding_value, previous_block):
    computed_state = padding_value ^ previous_block[byte_index] ^ guess
    print(f"Found valid padding for value {padding_value} with state: {hex(computed_state)}")
    return computed_state


def find_padding_one(p, iv, ciphertext_blocks):
    block_size = len(iv)
    byte_index = 15  # Target the last byte
    padding_value = 1  # Padding value to test
    block_index = 0
    current_block, previous_block = get_blocks(block_index, ciphertext_blocks, iv)
    state = init_state(block_size)
    return find_state(p, block_index, byte_index, iv, ciphertext_blocks, state, padding_value)


def find_full_state(p, iv, ciphertext_blocks):
    block_size = len(iv)
    block_index = 0
    current_block, previous_block = get_blocks(block_index, ciphertext_blocks, iv)

    state = init_state(block_size)

    for byte_index in range(block_size - 1, -1, -1):
        padding_value = block_size - byte_index

        find_state(p, block_index, byte_index, iv, ciphertext_blocks, state, padding_value)

    decrypted_block = bytearray(b1 ^ b2 ^ b3 for b1, b2, b3 in zip(current_block, previous_block, state))
    print(f"Decrypted block: {decrypted_block.decode()}")
    print(f"Current state: {binascii.hexlify(state)}")
    return state


p = remote("offsec-chalbroker.osiris.cyber.nyu.edu", 1512)
p.recvuntil(b"abc123):")
p.sendline(b"nam10102")

p.recvuntil(b"IV = ")
iv = p.recvline().strip()

p.recvuntil(b"Ciphertext = ")
ciphertext = p.recvline().strip()

p.recvuntil(b"Send me a message!\n")

work_iv = bytearray(binascii.unhexlify(iv))

work_ciphertext = bytearray(binascii.unhexlify(ciphertext))
print(f"IV: {iv}")
print(f"Ciphertext: {ciphertext}")

send_iv = binascii.hexlify(bytes(work_iv))
send_ciphertext = binascii.hexlify(bytes(work_ciphertext))
payload = send_iv + send_ciphertext
print(f"Sending: {payload}")
p.sendline(payload)

res = p.readline().strip()
print(f"Response: {res}")
p.recvuntil(b"Send me a message!\n")

ciphertext_blocks = split_into_blocks(work_ciphertext, len(work_iv))
print(f"Length of IV: {len(work_iv)}")
print(f"Length of ciphertext: {len(work_ciphertext)}")
print(f"Number of blocks: {len(ciphertext_blocks)}")

find_full_state(p, work_iv, ciphertext_blocks)
p.interactive()
