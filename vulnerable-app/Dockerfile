# SSRF Lab — vulnerable app image (Phase 1, level L0)
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so Docker can cache this layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY app.py .

# Flask listens on 5000 inside the container; compose publishes it as 8080.
EXPOSE 5000

CMD ["python", "app.py"]
