# sudo docker build -t pokemon .
# sudo docker run -d -p 1024:1024 --rm -it pokemon

FROM ubuntu@sha256:99c35190e22d294cdace2783ac55effc69d32896daaa265f0bbedbcde4fbe3e5

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept

COPY ynetd .
COPY flag.txt /opt/flag
COPY julekort .
COPY wrapper.py .
ENV PYTHONUNBUFFERED=1
# RUN chown -R root:root /home/ept
# RUN chmod  -R a+rx /home/ept
USER ept
CMD ./ynetd "python3 wrapper.py"
