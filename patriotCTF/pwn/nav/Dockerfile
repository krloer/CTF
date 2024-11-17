# sudo docker build -t navigator .
# sudo docker run -dp 8887:8887 --privileged navigator:latest

FROM ubuntu@sha256:77906da86b60585ce12215807090eb327e7386c8fafb5402369e421f44eff17e

RUN useradd -m ctf
WORKDIR /src
RUN apt update
RUN apt install xinetd -y

COPY ./navigator /src

CMD ["/bin/bash"]
