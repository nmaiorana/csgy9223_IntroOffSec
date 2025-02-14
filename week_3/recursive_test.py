
goal = 2147483647


def recursive_function(n):
    global moves

    if n != 0:
        recursive_function(n - 1)
        recursive_function(n - 1)
    moves += 1


i = 0
for i in range(10):
    moves = 0
    recursive_function(i)
    print(f'{i} moves: {moves}')

moves = 1
i = 1
while moves != 2147483647:
    moves = (2 * moves) + 1
    i += 1
print(f'{i} moves: {moves}')
