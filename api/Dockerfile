FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY secrets.ini /app/secrets.ini
COPY app/main.py /app/main.py