FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dashboard_api.py .
COPY static/ ./static/
EXPOSE 8080
CMD ["python", "dashboard_api.py"]
