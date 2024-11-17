FROM ubuntu@sha256:99c35190e22d294cdace2783ac55effc69d32896daaa265f0bbedbcde4fbe3e5

RUN apt-get update
RUN apt-get install -y python3

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept

COPY ynetd .
COPY flag.txt /opt/flag
COPY vm .
COPY wrapper.py .

USER ept
EXPOSE 1024
CMD ./ynetd -p 1024 "python3 wrapper.py"