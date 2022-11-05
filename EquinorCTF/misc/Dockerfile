FROM python:3.8-slim-buster

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept

COPY ynetd .
COPY fruits.py .
COPY vegetables.py .

RUN chown -R root:root /home/ept
RUN chmod -R a+rx /home/ept
USER ept
CMD ./ynetd 'python3 vegetables.py'
