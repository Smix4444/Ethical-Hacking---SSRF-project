# SSRF Lab — rebinding DNS server image (lab-only)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# DNS (udp/53) for rebind.lab + a small HTTP control API (80). Internal only.
EXPOSE 53/udp
EXPOSE 80

CMD ["python", "server.py"]
