def generate_value_with_n_bits(n):
    return (1 << n) - 1


condition_test = generate_value_with_n_bits(0x13)
print(hex(condition_test))
num1 = 0x12
num2 = condition_test ^ num1
print(hex(num1))
print(hex(num2))
print(hex(num1 ^ num2))
print(num1, num2)

print(condition_test)

result = 0
while condition_test:
    result += condition_test & 0x1
    condition_test = condition_test >> 1
print(result)
