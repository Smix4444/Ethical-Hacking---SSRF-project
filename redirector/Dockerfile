# SSRF Lab — attacker redirector image (lab-only, simulates a 302 redirect host)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Internal only; not published to the host.
EXPOSE 80

CMD ["python", "app.py"]
