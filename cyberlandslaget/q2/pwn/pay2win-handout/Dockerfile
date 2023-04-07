# sudo docker build -t pay2win .
# sudo docker run -d -p 1024:1024 --rm -it pay2win

FROM ubuntu:22.04

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept

COPY ynetd .
COPY flag.txt /opt/flag
COPY pay2win .

RUN chown -R root:root /home/ept
RUN chmod  -R a+rx /home/ept
USER ept
CMD ./ynetd ./pay2win
