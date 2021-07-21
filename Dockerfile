FROM python:3-slim AS virusdeck-collectors
WORKDIR /usr/src/app
COPY ./collectors/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ./models ./models
COPY ./collectors ./collectors
CMD ["python", "./collectors/main.py"]

FROM python:3-slim AS virusdeck-twitter
WORKDIR /usr/src/app
COPY ./twitter/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ./models ./models
COPY ./twitter ./twitter
CMD ["python", "./twitter/main.py"]

FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim AS virusdeck-web
COPY ./web/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
ENV MODULE_NAME=web
COPY ./models ./app/models
COPY ./web /app/web