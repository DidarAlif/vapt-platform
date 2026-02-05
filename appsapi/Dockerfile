# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies and Nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (latest version)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    && unzip nuclei_3.3.7_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.7_linux_amd64.zip \
    && nuclei -update-templates

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create work directory for scan outputs
RUN mkdir -p work

# Railway provides PORT env variable
ENV PORT=8000
EXPOSE $PORT

# Start the application using Railway's PORT
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
