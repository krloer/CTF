FROM ubuntu:22.04

RUN useradd -d /home/ctf -m -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
WORKDIR /home/ctf

COPY flag.txt pethotel ynetd .
RUN chown root:root flag.txt pethotel ynetd
RUN chmod 644 flag.txt
RUN chmod 755 pethotel ynetd
USER ctf
CMD ./ynetd ./pethotel

