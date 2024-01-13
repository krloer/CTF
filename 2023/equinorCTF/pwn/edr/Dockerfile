FROM ubuntu:22.04

# Install supervisord
RUN apt update && apt install -y supervisor socat rsyslog 

RUN useradd -d /home/ept/ -m -p ept -s /bin/bash ept
RUN echo "ept:ept" | chpasswd

WORKDIR /home/ept
COPY ept_edr /home/ept
COPY ynetd /home/ept
COPY flag.txt /opt/flag
COPY process_monitor /home/ept/process_monitor
RUN chmod +x /home/ept/ept_edr /home/ept/process_monitor

# Your other setup steps, like installing socat, service X, and service Y

EXPOSE 1024

COPY ./supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord"]

