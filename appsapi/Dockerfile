# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (latest version) with all templates
ENV NUCLEI_VERSION=3.3.7
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && unzip nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei

# Download Nuclei templates (9000+ templates)
RUN mkdir -p /root/nuclei-templates \
    && nuclei -update-templates -silent \
    && echo "Templates downloaded successfully"

# Set environment variables for Nuclei
ENV NUCLEI_TEMPLATES_PATH=/root/nuclei-templates
ENV HOME=/root

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create work directory for scan outputs
RUN mkdir -p work && chmod 777 work

# Railway provides PORT env variable
ENV PORT=8000
EXPOSE $PORT

# Start the application
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
