FROM python:alpine

COPY requirements.txt app/requirements.txt

WORKDIR /app

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt

COPY *.py /app/
COPY .env /app

# ENTRYPOINT ["python3"]

# CMD ["event_monitor.py"]
