FROM python:3-slim AS virusdeck-collectors
WORKDIR /usr/src/app
COPY virusdeck/collectors/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY virusdeck/collectors ./virusdeck/collectors
CMD ["python", "-m", "virusdeck.collectors.main"]

FROM python:3-slim AS virusdeck-twitter
WORKDIR /usr/src/app
COPY virusdeck/twitter/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY virusdeck/models ./virusdeck/models
COPY virusdeck/twitter ./virusdeck/twitter
CMD ["python", "-m", "virusdeck.twitter.main"]

FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim AS virusdeck-web
COPY virusdeck/web/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
ENV MODULE_NAME=virusdeck.web
COPY virusdeck/models ./app/virusdeck/models
COPY virusdeck/web ./app/virusdeck/web