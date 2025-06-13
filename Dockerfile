# Use Google's official Python base image with Debian
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies, Google Cloud SDK, and jq
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    lsb-release \
    apt-transport-https \
    ca-certificates \
    bash \
    jq \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && apt-get update && apt-get install -y google-cloud-sdk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY detector.sh .

# Make the script executable
RUN chmod +x detector.sh
RUN sed -i 's/\r$//' detector.sh
# Create empty state files if they don't exist (will be populated from GCS)
RUN touch bucket_security_state.json encrypted_state.json encrypted_files.txt

# Use a non-root user (for security best practices)
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Configure the container to run the web server
ENV PORT 8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 main:app 