from z3 import Int, Solver, sat

# declare three integers, the goal of our solver
x = Int('x')
y = Int('y')
z = Int('z')

# create solver and enforce constraints per the program control flow
s = Solver()
s.add(x > 2, y > 2, z > 2)
s.add(x < 0x100, y < 0x100, z < 0x100)
s.add(x <= y, y <= z)
s.add(x * y * z == 778910)
s.add(z % x == 37)

# solve!
assert s.check() == sat, "Error, not satisfiable!"
print(s.model())
# prints
# [x = 73,
#  z = 110,
#  y = 97,
#  div0 = [else -> 1],
#  mod0 = [else -> 0]]
