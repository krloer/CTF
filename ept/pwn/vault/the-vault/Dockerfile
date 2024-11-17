# sudo docker build -t vcs_first .
# sudo docker run -d -p 1024:1024 --rm -it vcs_first

FROM ubuntu:20.04

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept

COPY ynetd .
COPY flag.txt /opt/flag
COPY vcs_first .

RUN chown -R root:root /home/ept
RUN chmod  -R a+rx /home/ept
USER ept
CMD ./ynetd ./vcs_first