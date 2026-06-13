FROM python:3.13-slim

WORKDIR /app

# Install system dependencies for dkimpy and DNS resolution
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data at build time so it's baked into the image
RUN python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab'); nltk.download('stopwords'); nltk.download('wordnet')"

COPY . .

EXPOSE 8001

CMD ["python", "api_server.py"]
