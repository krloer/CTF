# README

## Intro
We are sick of wack EDR solutions, so we have created our own user land EDR for linux. The EDR will make sure that the target process only executes allowed syscalls. If it tries anything else, it will be killed.

There is also a DLP solution included that will stop any attemps of data exfil. 

For a proper test of the EDR, we are running the process_monitor from the procmon challenge. But this time its protected by the EDR. Can you still get the flag?

## Debugging
To properly debug this challenge, setup a dockerenv using  `Dockerfile.dev`

```sh
#build
docker build -t eptedr.dev - < Dockerfile.dev 
#run
docker run --rm -it -p 1024:1024 -v $(pwd):/home/ept eptedr.dev
#get extra shell
docker exec -it eptedr.dev /bin/bash
#start the process_monitor in dev container:
socat TCP-LISTEN:1024,fork,reuseaddr EXEC:/home/ept/process_monitor
#then, finally run the edr in the container.
/home/ept/ept_edr process_monitor
```

You can now debug this using gdb. As ept_edr is a forking service, the easiest is to connect, get the fork running, and then connect with ``gdb --pid=`pidof ept_edr` ``
