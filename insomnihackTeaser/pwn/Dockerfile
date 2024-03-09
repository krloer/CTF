FROM ubuntu@sha256:bbf3d1baa208b7649d1d0264ef7d522e1dc0deeeaaf6085bf8e4618867f03494

RUN apt-get update

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

ARG FLAG="flag{dummy}"
RUN echo "$FLAG" > flag.txt
RUN chmod 644 flag.txt

COPY vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790 ynetd /home/ctf/
RUN chown -R root:root /home/ctf
RUN chmod 755 /home/ctf ynetd vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790

USER ctf
EXPOSE 1024
CMD ./ynetd -p 1024 ./vaulty-f5d5d6e5471b625659733cff28ece1b876c7fc228b014ce1f1bad7aa768c3790
