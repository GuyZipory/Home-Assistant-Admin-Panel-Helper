FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install fastapi uvicorn requests

EXPOSE 80

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
