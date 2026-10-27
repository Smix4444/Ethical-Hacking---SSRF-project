# SSRF Lab — mock cloud metadata service image (FAKE data, lab-only)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Real IMDS answers on port 80; we mirror that. Not published to the host.
EXPOSE 80

CMD ["python", "app.py"]
