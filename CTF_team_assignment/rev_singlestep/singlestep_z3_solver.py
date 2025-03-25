from z3 import Int, Solver, sat

# declare the variable
num = Int('num')

# create solver and enforce constraints
s = Solver()
s.add(num >= 0, num < 256)
s.add(num % 5 == 4)

# solve!
assert s.check() == sat, "Error, not satisfiable!"
model = s.model()
number = model[num].as_long()
print(model)

# convert the number to a single byte
byte_string = number.to_bytes(1, byteorder='little')

# print the character of the single byte
print(byte_string[0])