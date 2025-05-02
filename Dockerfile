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
COPY *.py .
COPY qrcode.jpg .

# Run the debug script first, then run the main application
CMD ["sh", "-c", "python debug_telegram.py && python otp_sender.py"]
