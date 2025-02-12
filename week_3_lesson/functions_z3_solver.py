from z3 import Solver, BitVec, And, sat


def perform_mod(a, b):
    return a % b


def check_bounds(x, y, z):
    return And(x < 0x10000, y < 0x10000, z < 0x10000)


def check(x, y, z):
    return And(x * y == -1508619901,
               perform_mod(z, 73) == 28,
               y / z == 9,
               y + z == 53798)


# declare three integers, the goal of our solver
x = BitVec('x', 32)
y = BitVec('y', 32)
z = BitVec('z', 32)

# create solver and enforce constraints per the program control flow
s = Solver()
s.add(x > 0, y > 0, z > 0)
s.add(check_bounds(x, y, z) == True)
s.add(check(x, y, z) == True)

# solve!
assert s.check() == sat, "Error, not satisfiable!"
print(s.model())
# prints [x = 57005, y = 48879, z = 4919], x = 0xdead, y = 0xbeef, z = 0x1337
# same as above!
