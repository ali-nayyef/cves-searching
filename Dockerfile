FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

# Data volume for DB + logs
RUN mkdir -p /app/data
WORKDIR /app/data

CMD ["python", "/app/bot.py"]
