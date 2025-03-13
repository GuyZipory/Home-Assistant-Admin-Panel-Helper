FROM ghcr.io/hassio-addons/base-python:latest

RUN pip install fastapi uvicorn requests

WORKDIR /app
COPY . /app

CMD [ "python", "main.py" ]
