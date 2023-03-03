from angr import *
from IPython import embed

project = Project('./check_password', main_opts={'base_addr': 0}, auto_load_libs=False) # 0 i angr's virtuelle minne

initial_state = project.factory.entry_state()
print(initial_state)

sm = project.factory.simgr(initial_state)

loss = 0x10ef #kun 4 siste fra 101127 og 101110 fordi vi setter 0 som base_addr
win = 0x1119

sm.explore(find=win, avoid=loss)
print(sm)

flag = sm.found[0].posix.dumps(0).decode()
print(flag)

embed() #interactive