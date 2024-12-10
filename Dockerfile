FROM python:3.9-slim

# Install system dependencies required for pyzbar
RUN apt-get update && apt-get install -y \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application files
COPY otp_sender.py .
COPY qrcode.jpg .

# Run the application
CMD ["python", "otp_sender.py"]
