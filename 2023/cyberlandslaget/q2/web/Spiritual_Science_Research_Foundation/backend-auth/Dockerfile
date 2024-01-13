FROM python:3.10

RUN mkdir /app
WORKDIR /app
COPY *.py ./
COPY requirements.txt ./
COPY flag.txt ./
RUN apt-get -y update && apt-get upgrade -y
RUN apt-get install -y python3 python3-pip python3-dev libpq-dev build-essential
RUN pip install -r requirements.txt --no-cache-dir

ENV POSTGRES_PASSWORD xxxxxxxxxxxx
ENV POSTGRES_USER user
ENV POSTGRES_HOST postgress-db

EXPOSE 80
CMD [ "python3", "app.py"]

