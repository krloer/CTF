FROM ubuntu:18.04
RUN apt update && apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa && install python3.8 
RUN ln -s /usr/bin/pip3 /usr/bin/pip && \
    ln -s /usr/bin/python3.8 /usr/bin/python
