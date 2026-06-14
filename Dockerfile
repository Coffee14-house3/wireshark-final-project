# Use an official lightweight Python image
FROM python:3.10-slim

# Install system-level networking tools required by PyShark for packet sniffing
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all backend files into the container
COPY backend/ .

# Expose the port your Flask app runs on
EXPOSE 5000

# Command to start the Flask-SocketIO server
CMD ["python", "app.py"]
