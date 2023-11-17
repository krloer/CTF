#!/usr/bin/env bash
for ((sid=0; sid < 256; sid++)); do
	echo $sid
	ltrace ./chal 0 0 $sid
	./chal 0 0 $sid
done;
