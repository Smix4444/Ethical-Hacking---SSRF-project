# SSRF Lab — dashboard image (lab-only, read-only + button-driven)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# The toolkit is mounted read-only at /app/toolkit by docker-compose (reused,
# not duplicated). Flask listens on 5000; compose publishes it as host 8099.
EXPOSE 5000

CMD ["python", "app.py"]
