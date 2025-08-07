# Use official Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY app/ ./

# Expose Flask port
EXPOSE 5000

# Start the Python app
CMD ["python", "unifi_whitelist_server.py"]
