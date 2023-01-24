#!/bin/bash
docker rm -f vegetables
docker build -t vegetables .
docker run --name=vegetables --rm -p1024:1024 -it vegetables
