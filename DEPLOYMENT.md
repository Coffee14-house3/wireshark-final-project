# Deployment Guide - Wireshark Network Packet Analyzer

## Quick Start (Local with Docker)

### Prerequisites
- Docker & Docker Compose installed
- Port 80 and 5000 available

### Run Locally
```bash
docker-compose up -d
```

Then visit: **http://localhost**

---

## Tencent Cloud EdgeOne Deployment

### Method 1: Using EdgeOne Makers (Web Interface)

1. Go to **Tencent Cloud Console** → **EdgeOne** → **EdgeOne Makers**
2. Click **Create Project**
3. Select your GitHub repository: `Coffee14-house3/wireshark-final-project`
4. Fill in:
   - **Project Name**: `wireshark-analyzer`
   - **Language**: Docker
   - **Branch**: main
   - **Region**: Singapore (closest to Asia)
5. Add Environment Variables:
   ```
   FLASK_ENV=production
   SECRET_KEY=your-secret-key
   PORT=5000
   ```
6. Click **Deploy**

### Method 2: Using Tencent Cloud CVM (Cloud Virtual Machine)

#### Step 1: Launch a CVM Instance
```bash
# SSH into your CVM
ssh -i your-key.pem ubuntu@your-instance-ip
```

#### Step 2: Install Docker
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

#### Step 3: Clone and Deploy
```bash
git clone https://github.com/Coffee14-house3/wireshark-final-project.git
cd wireshark-final-project
docker-compose up -d
```

#### Step 4: Configure Firewall
- In Tencent Cloud Console → CVM Security Groups
- Add Inbound Rule:
  - Protocol: TCP
  - Port: 80, 443, 5000
  - Source: 0.0.0.0/0

---

## Tencent Cloud Serverless (SCF) - Function Computing

Not recommended for this application because:
- ❌ WebSocket connections not persistent
- ❌ Packet capture requires long-running processes
- ❌ Complex state management

**Use CVM or Docker instead.**

---

## Troubleshooting

### Port Already in Use
```bash
# Find process using port 5000
lsof -i :5000
# Kill process
kill -9 <PID>
```

### WebSocket Connection Failed
- Check firewall allows port 5000
- Verify CORS settings in `app.py`
- Check browser console for errors

### Packet Capture Not Working
- Application needs root/admin privileges
- On CVM: Use `sudo docker-compose up -d` or run container with elevated privileges
- May not work in container without proper privileges - use native installation on host

---

## File Descriptions

| File | Purpose |
|------|---------|
| `Dockerfile` | Container image definition |
| `docker-compose.yml` | Local multi-container setup with nginx reverse proxy |
| `nginx.conf` | Nginx configuration for production |
| `tencent.yml` | Tencent Cloud EdgeOne configuration |
| `.cloudignore` | Files to exclude from cloud upload |
| `DEPLOYMENT.md` | This file |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | production | Flask environment mode |
| `SECRET_KEY` | (required) | Session encryption key |
| `PORT` | 5000 | Server port |
| `FLASK_DEBUG` | 0 | Debug mode (0 for production) |

---

## Maintenance

### View Logs
```bash
docker-compose logs -f wireshark-backend
```

### Stop Application
```bash
docker-compose down
```

### Update Application
```bash
git pull origin main
docker-compose up -d --build
```

---

## Security Notes

1. ✅ Always use HTTPS in production
2. ✅ Change `SECRET_KEY` to a strong random value
3. ✅ Restrict firewall to necessary ports only
4. ✅ Keep dependencies updated
5. ✅ Use environment variables for sensitive data (not hardcoded)

---

For more help, visit:
- Tencent Cloud Docs: https://cloud.tencent.com/document
- Flask-SocketIO: https://python-socketio.readthedocs.io/
- Docker: https://docs.docker.com/
