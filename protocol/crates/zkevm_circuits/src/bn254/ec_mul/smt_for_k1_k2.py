from z3 import *

def find_solution(k1, expr):
    solver = Solver()

    lambd = Int('lambd')
    a1 = Int('a1')
    b1 = Int('b1')
    a2 = Int('a2')
    b2 = Int('b2')
    n = Int('n')
    g1 = Int('g1')
    g2 = Int('g2')
    c1 = Int('c1')
    c2 = Int('c2')
    q1 = Int('q1')
    q2 = Int('q2')
    k2 = Int('k2')
    k2_lambda = Int('k2_lambda')
    k = Int('k')

    solver.add(lambd == 4407920970296243842393367215006156084916469457145843978461)
    solver.add(a1 == 0x89d3256894d213e3)
    solver.add(b1 == -0x6f4d8248eeb859fc8211bbeb7d4f1128)
    solver.add(a2 == 0x6f4d8248eeb859fd0be4e1541221250b)
    solver.add(b2 == 0x89d3256894d213e3)
    solver.add(n == 21888242871839275222246405745257275088548364400416034343698204186575808495617)
    solver.add(g1 == 782660544089080853078787955015628534157)
    solver.add(g2 == 0x2d91d232ec7e0b3d7)
    solver.add(c1 == (g2 * k) / (2**256))
    solver.add(c2 == (g1 * k) / (2**256))
    solver.add(q1 == c1 * b1)
    solver.add(q2 == -(c2 * b2))
    solver.add(k2 == q2 - q1)
    solver.add(k2_lambda == (k2 * lambd) % n)
    solver.add(k1 == k - k2_lambda)
    solver.add(k >= 0)
    solver.add(k < n)
    solver.add(eval(expr))

    res = solver.check()
    if res == sat:
        m = solver.model()
        print("Solution found:")
        print(m)
    elif res == unsat:
        print("Solution does not exist")
    else:
        print("Unknown if solution exists")

exprs = [
    'k1 == 0',
    'k1 < 0',
    'k2 < 0',
    'k1 == 166069116403752002167832803607207952478',
    'k1 > 166069116403752002167832803607207952478',
    'k2 == -160042871798160843020181221280528662475',
    'k2 < -160042871798160843020181221280528662475',
    'k2 == 4965661367192848883',
    'k2 > 4965661367192848883',
]
for e in exprs:
    k1 = Int('k1')
    print('Solving for', e)
    find_solution(k1, e)
    print()
