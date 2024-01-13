#!/usr/bin/env python3
import angr

simgr = angr.Project('./test').factory.simgr()
simgr.explore(find=lambda s: b"Flag is correct!" in s.posix.dumps(1))
flag = simgr.found[0].posix.dumps(0).decode()
print(flag)