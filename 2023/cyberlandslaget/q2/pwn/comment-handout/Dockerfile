FROM ubuntu:22.04

RUN useradd -d /home/ctf -m -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
WORKDIR /home/ctf

COPY flag.txt review  ynetd .
RUN chown root:root flag.txt review ynetd
RUN chmod 644 flag.txt
RUN chmod 755 review ynetd
USER ctf
CMD ./ynetd ./review

