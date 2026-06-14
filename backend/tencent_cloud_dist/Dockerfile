# Use an official lightweight Python image
FROM python:3.10-slim

# Install system-level networking tools required by Scapy for packet sniffing
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your backend files (including app.py, templates, etc.) into the container
COPY . .

# Expose the port your Flask app runs on
EXPOSE 5000

# Command to start the Flask-SocketIO server
CMD ["python", "app.py"]