FROM python:3.11-slim

LABEL maintainer="@irfan-sec"
LABEL description="Blue-sec - Advanced Bluetooth Security Testing Framework"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    bluetooth \
    bluez \
    libbluetooth-dev \
    build-essential \
    gcc \
    libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p reports data/payloads config

# Make blue-sec.py executable
RUN chmod +x blue-sec.py

# Set entrypoint
ENTRYPOINT ["python3", "blue-sec.py"]
CMD ["--help"]
