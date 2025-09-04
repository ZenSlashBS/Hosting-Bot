FROM python:3.9-slim
RUN apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
COPY requirements.txt .
COPY Procfile .
COPY register.html .
COPY index.html .
COPY layout.html .
COPY login.html .
COPY script.js .
COPY style.css .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]
