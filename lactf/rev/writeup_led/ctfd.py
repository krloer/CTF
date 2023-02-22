from angr import *
from IPython import embed

project = Project('./ctfd_plus', main_opts={'base_addr': 0}, auto_load_libs=False) # 0 i angr's virtuelle minne

initial_state = project.factory.entry_state()
print(initial_state)

sm = project.factory.simgr(initial_state)

win = 0x1127 #kun 4 siste fra 101127 og 101110 fordi vi setter 0 som base_addr
loss = 0x1110

sm.explore(find=win, avoid=loss)
print(sm)

flag = sm.found[0].posix.dumps(0).decode()
print(flag)

# embed() #interactive