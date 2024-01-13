import angr

simgr = angr.Project('check_password').factory.simgr()
simgr.explore(find=lambda s: b"Congratulations! The flag is" in s.posix.dumps(1))
flag = simgr.found[0].posix.dumps(0).decode()
print(flag)