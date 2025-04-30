FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir flask pymongo

EXPOSE 9000

CMD python3 server.py
