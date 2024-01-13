FROM ubuntu:22.04

RUN apt-get update && apt-get install -y g++-multilib gcc-multilib build-essential socat

RUN mkdir /data
WORKDIR /data
COPY general.cpp .
ARG VULN_1
ARG BUFFER_SIZE
ARG VULN_2
ARG USERNAME_SIZE
RUN gcc -fno-stack-protector -m32 general.cpp -o general -D"VULN_1=${VULN_1}" -D"BUFFER_SIZE=${BUFFER_SIZE}" -D"VULN_2=${VULN_2}" -D"USERNAME_SIZE=${USERNAME_SIZE}" 
RUN chmod +x general
COPY flag.txt .

EXPOSE 8080

CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./general,pty,stderr,setsid,sigint,sane,raw,echo=0