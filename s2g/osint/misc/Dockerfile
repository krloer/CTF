FROM python:3.10-slim

RUN apt update && apt install socat -y
RUN useradd -M ctf

WORKDIR /app

COPY app.py .
COPY flag.py .

RUN chown -R root:root /app
RUN chmod -R 555 /app

ENTRYPOINT socat TCP4-LISTEN:1337,fork,reuseaddr EXEC:/app/app.py,su=ctf