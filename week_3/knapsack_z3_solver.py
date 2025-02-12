from z3 import Int, Solver, sat

# declare the predefined integers

var_0 = 1605
var_1 = 215
var_2 = 275
var_3 = 335
var_4 = 355
var_5 = 420
var_6 = 580

# declare the variables
num1 = Int('num1')
num2 = Int('num2')
num3 = Int('num3')
num4 = Int('num4')
num5 = Int('num5')
num6 = Int('num6')

# create solver and enforce constraints per the program control flow
s = Solver()
s.add(num1 >= 0)
s.add(num2 >= 0)
s.add(num3 >= 0)
s.add(num4 >= 0)
s.add(num5 >= 0)
s.add(num6 >= 0)
s.add(var_6 * num6 + var_1 * num1 + var_2 * num2 + var_3 * num3 + var_4 * num4 + var_5 * num5 == var_0)

# solve!
assert s.check() == sat, "Error, not satisfiable!"
print(s.model())
