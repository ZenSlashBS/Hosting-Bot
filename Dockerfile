FROM python:3.9-slim
RUN apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
COPY requirements.txt .
COPY Procfile .
COPY static/ static/
COPY templates/ templates/
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]
