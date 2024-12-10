#!/bin/bash

# Update and install dependencies
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker's GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update and install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Add current user to docker group
sudo usermod -aG docker $USER

# Create app directory
mkdir -p ~/otp-sender
cd ~/otp-sender

# Extract application files (assuming they're already uploaded)
tar -xzf ../otp-sender.tar.gz

# Build Docker image
docker build -t otp-sender .

# Run container
docker run -d --restart unless-stopped otp-sender

echo "Setup complete! OTP sender is now running in a Docker container."
