FROM python:3.10-slim
WORKDIR /app
COPY ./server_escaped.py /app
RUN pip install --no-cache-dir flask pymongo
EXPOSE 9000
CMD python3 server_escaped.py
