FROM alpine@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a

RUN apk update
RUN apk add --no-cache socat
RUN apk add --no-cache make
RUN apk add --no-cache cmake
RUN apk add --no-cache linux-headers
RUN apk add --no-cache texinfo
RUN apk add --no-cache gcc
RUN apk add --no-cache g++
RUN apk add --no-cache gdb
RUN apk add --no-cache --virtual .build-deps g++ python3-dev capstone libffi-dev openssl-dev py3-pip && \
    apk add --no-cache --update python3
RUN pip install unicorn --upgrade
COPY ./make_capstone.sh /make_capstone.sh
RUN wget --no-verbose -O "capstone-5.0.tar.gz" "https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.tar.gz"
RUN /make_capstone.sh
# RUN pip install pwntools

RUN adduser -D ctf

COPY ./flag /flag
COPY ./pong /pong

EXPOSE 1440
EXPOSE 2159

USER ctf

# RUN /bin/sh -c "socat tcp-l:1440,reuseaddr,fork exec:'/pong'"