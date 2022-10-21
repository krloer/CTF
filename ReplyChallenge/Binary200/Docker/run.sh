#!/bin/sh

docker build -t "bin200_image" .
docker run --read-only --name="bin200_container" bin200_image
