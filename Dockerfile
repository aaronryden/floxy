# Use an official Python image that supports multiple architectures (ARM, x86)
FROM --platform=$TARGETPLATFORM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    certbot \
    gnupg \
    curl \
    && rm -rf /var/lib/apt/lists/*

  # Copy dependency file(s)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project
COPY . .

# make directory selfsigned
RUN mkdir -p /app/selfsigned

RUN ls -la /app

# Expose port (adjust if needed)
EXPOSE 80
EXPOSE 443

# Run the app
CMD ["python", "server.py"]
