FROM python:3-slim

WORKDIR /usr/src/app

RUN pip install -U pip

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY secrets.ini ./
COPY ./app/ ./

CMD ["python", "main.py"]