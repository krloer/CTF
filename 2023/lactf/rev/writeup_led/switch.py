from angr import *
from IPython import embed
import claripy

project = Project('./switcheroo', main_opts={}, auto_load_libs=False) # 0 i angr's virtuelle minne

flag = claripy.BVS('flag', 64 * 8)

initial_state = project.factory.entry_state(stdin=flag)
print(initial_state)

for c in flag.chop(8):
    initial_state.solver.add(initial_state.solver.And(c <= chr(0x7E), c >= chr(0x21)))

initial_state.solver.add(flag.chop(8)[0] == 'l')
initial_state.solver.add(flag.chop(8)[1] == 'a')
initial_state.solver.add(flag.chop(8)[2] == 'c')
initial_state.solver.add(flag.chop(8)[3] == 't')
initial_state.solver.add(flag.chop(8)[4] == 'f')
initial_state.solver.add(flag.chop(8)[5] == '{')
initial_state.solver.add(flag.chop(8)[-1] == '}')


sm = project.factory.simgr(initial_state)

win = 0x40107c
loss = [0x40108b, 401076] 

while True:
    sm.explore(find=win, avoid=loss)
    print(sm)
    if len(sm.found) != 0:
        break
    sm.drop(stash="avoid")



flag = sm.found[0].posix.dumps(0).decode()
print(flag)

# embed() #interactive