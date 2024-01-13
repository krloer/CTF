# Tips and tricks

## Debugging
This challenge runs on Ubuntu 20.04. If you don't have this operating system installed, the best way to debug is to run the challenge in a Docker environment.
I've attached a `Dockerfile.dev` that I use for pwn challenges.
To run:

```bash
# Build the Docker container
docker build -t vcs_first.dev - < Dockerfile.dev 
# Run the Docker container
docker run --rm -it -p 1024:1024 -v $(pwd):/home/ept vcs_first.dev
# Get a shell inside the container
docker exec -it vcs_first.dev /bin/bash
```

The development container comes with `pwndbg` preinstalled. `Pwndbg` offers many features that simplify heap exploitation.
[Full documentation can be found here.](https://browserpwndbg.readthedocs.io/en/docs/commands/heap/heap/)

Some useful commands include:

- `bins` - Lists all the bins, including tcache.
- `tcachebins` - Shows tcache bins only.
- `vis` - Displays all the malloced heap chunks.

