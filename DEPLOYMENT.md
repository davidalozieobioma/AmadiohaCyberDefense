# Amadioha Cyber Defense — Deployment Guide

Complete instructions for deploying Amadioha to Docker, Heroku, AWS, and other platforms.

---

## 📋 Table of Contents

1. [Docker (Local & Remote)](#docker-local--remote)
2. [Heroku](#heroku)
3. [AWS (EC2, ECS, Elastic Beanstalk)](#aws)
4. [Production Checklist](#production-checklist)

---

## 🐳 Docker (Local & Remote)

### Prerequisites

- Docker Desktop installed ([download](https://www.docker.com/products/docker-desktop))
- Docker Hub account (for pushing images)

### Build the Docker Image

```bash
# Build the image locally
docker build -t amadioha-cyber-defense:latest .

# Tag for Docker Hub
docker tag amadioha-cyber-defense:latest yourusername/amadioha-cyber-defense:latest
```

### Run Locally with Docker

```bash
# Run from built image
docker run -p 5000:5000 amadioha-cyber-defense:latest

# Or use docker-compose (recommended for development)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop container
docker-compose down
```

### Access the Dashboard

```
http://localhost:5000
```

### Push to Docker Hub

```bash
# Login to Docker Hub
docker login

# Push image
docker push yourusername/amadioha-cyber-defense:latest

# Verify
docker pull yourusername/amadioha-cyber-defense:latest
```

### Run from Docker Hub

```bash
docker run -p 5000:5000 yourusername/amadioha-cyber-defense:latest
```

---

## 🚀 Heroku

### Prerequisites

- Heroku account ([signup](https://www.heroku.com))
- Heroku CLI installed ([download](https://devcenter.heroku.com/articles/heroku-cli))

### Deploy in 5 Steps

#### Step 1: Login to Heroku

```bash
heroku login
```

#### Step 2: Create a Heroku App

```bash
# Create app with unique name
heroku create amadioha-cyber-defense

# Or specify a custom name
heroku create my-amadioha-app
```

#### Step 3: Set Environment Variables (Optional)

```bash
heroku config:set FLASK_ENV=production
heroku config:set WORKERS=4
```

#### Step 4: Deploy

```bash
git push heroku main
```

Or if deploying via Docker:

```bash
# Build and push Docker image to Heroku Registry
heroku container:push web

heroku container:release web
```

#### Step 5: Open Your App

```bash
heroku open

# Or visit manually
https://amadioha-cyber-defense.herokuapp.com
```

### View Logs

```bash
heroku logs --tail
```

### Troubleshooting Heroku

```bash
# Check app status
heroku status

# View config
heroku config

# View recent releases
heroku releases

# Restart app
heroku restart

# Scale dynos
heroku ps:scale web=1

# View all processes
heroku ps
```

---

## ☁️ AWS

### Option 1: EC2 (Virtual Machine)

#### Prerequisites
- AWS account
- EC2 instance running (Ubuntu 22.04 LTS recommended)
- SSH access to instance

#### Deploy Steps

##### 1. SSH into EC2 Instance

```bash
ssh -i your-key.pem ubuntu@your-instance-ip
```

##### 2. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install -y python3.11 python3-pip python3-venv git

# Install Docker (optional)
sudo apt install -y docker.io
sudo usermod -aG docker $USER
```

##### 3. Clone Repository

```bash
git clone https://github.com/yourusername/AmadiohaCyberDefense.git
cd AmadiohaCyberDefense
```

##### 4. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

##### 5. Run with Gunicorn

```bash
# Direct run
gunicorn -w 4 -b 0.0.0.0:5000 amadioha.web:app

# Or use systemd service (recommended)
sudo nano /etc/systemd/system/amadioha.service
```

**Systemd Service File** (`/etc/systemd/system/amadioha.service`):

```ini
[Unit]
Description=Amadioha Cyber Defense
After=network.target

[Service]
Type=notify
User=ubuntu
WorkingDirectory=/home/ubuntu/AmadiohaCyberDefense
Environment="PATH=/home/ubuntu/AmadiohaCyberDefense/venv/bin"
ExecStart=/home/ubuntu/AmadiohaCyberDefense/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 amadioha.web:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

##### 6. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable amadioha
sudo systemctl start amadioha
sudo systemctl status amadioha
```

##### 7. Configure Nginx Reverse Proxy (Optional)

```bash
sudo apt install -y nginx

sudo nano /etc/nginx/sites-available/amadioha
```

**Nginx Config**:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/amadioha /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

##### 8. Set Up HTTPS (Let's Encrypt)

```bash
sudo apt install -y certbot python3-certbot-nginx

sudo certbot --nginx -d your-domain.com
```

---

### Option 2: AWS ECS (Elastic Container Service)

#### Prerequisites
- Docker image pushed to ECR (Elastic Container Registry)
- AWS CLI configured

#### Steps

##### 1. Create ECR Repository

```bash
aws ecr create-repository --repository-name amadioha-cyber-defense --region us-east-1
```

##### 2. Push Docker Image to ECR

```bash
# Get ECR login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

# Build and tag
docker build -t amadioha-cyber-defense .
docker tag amadioha-cyber-defense:latest 123456789.dkr.ecr.us-east-1.amazonaws.com/amadioha-cyber-defense:latest

# Push
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/amadioha-cyber-defense:latest
```

##### 3. Create ECS Cluster

```bash
aws ecs create-cluster --cluster-name amadioha-cluster
```

##### 4. Register Task Definition

Create `task-definition.json`:

```json
{
  "family": "amadioha-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "amadioha",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/amadioha-cyber-defense:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "hostPort": 5000,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/amadioha",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Register:

```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

##### 5. Create Service

```bash
aws ecs create-service \
  --cluster amadioha-cluster \
  --service-name amadioha-service \
  --task-definition amadioha-task \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

---

### Option 3: AWS Elastic Beanstalk

#### Prerequisites
- AWS account
- Elastic Beanstalk CLI installed

#### Steps

##### 1. Initialize EB Environment

```bash
eb init -p docker amadioha-cyber-defense --region us-east-1
```

##### 2. Create Environment

```bash
eb create amadioha-env
```

##### 3. Deploy

```bash
eb deploy
```

##### 4. Open Application

```bash
eb open
```

##### 5. View Logs

```bash
eb logs
```

---

## ✅ Production Checklist

### Security
- [ ] Use HTTPS/TLS (Let's Encrypt or AWS ACM)
- [ ] Set `FLASK_ENV=production`
- [ ] Use environment variables for secrets
- [ ] Configure CORS headers if needed
- [ ] Set up Web Application Firewall (WAF)
- [ ] Enable authentication/authorization
- [ ] Regularly update dependencies: `pip list --outdated`

### Performance
- [ ] Use Gunicorn with multiple workers (4-8)
- [ ] Enable caching headers
- [ ] Use CDN for static files
- [ ] Set up monitoring and logging
- [ ] Configure auto-scaling if on cloud platform
- [ ] Use production database (not in-memory storage)

### Monitoring & Logging
- [ ] CloudWatch (AWS) or equivalent logging
- [ ] Application performance monitoring (APM)
- [ ] Error tracking (Sentry)
- [ ] Health checks enabled
- [ ] Uptime monitoring

### Application Improvements for Production
- [ ] Store results in database (SQLite/PostgreSQL) instead of memory
- [ ] Add rate limiting
- [ ] Implement request validation
- [ ] Add comprehensive error handling
- [ ] Set up audit logging
- [ ] Configure CORS properly
- [ ] Add API key authentication

### Example: Add PostgreSQL for Production

```bash
# Install psycopg2
pip install psycopg2-binary sqlalchemy

# Update requirements.txt
echo "psycopg2-binary==2.9.9" >> requirements.txt
echo "SQLAlchemy==2.0.23" >> requirements.txt
```

Then modify `amadioha/web.py` to use PostgreSQL:

```python
from sqlalchemy import create_engine
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///amadioha.db")
engine = create_engine(DATABASE_URL)

# Store scan results in database instead of memory
```

---

## 📊 Cost Estimation

### Platform Costs (as of Feb 2026)

| Platform | Free Tier | Paid | Notes |
|----------|-----------|------|-------|
| **Heroku** | ❌ Discontinued | $7/month | Simple, easiest deployment |
| **AWS EC2** | 12 months | $10-50/month | Full control, scalable |
| **AWS ECS/Fargate** | 1M invocations/month | $15-100/month | Managed containers |
| **Docker Hub** | ✓ Unlimited public | $5/month | Image registry only |
| **AWS Elastic Beanstalk** | ✓ Limited | $0-50/month | Managed platform |

---

## 🔄 CI/CD Pipeline (GitHub Actions)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Heroku

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Heroku CLI
        run: npm install -g heroku
      
      - name: Deploy to Heroku
        env:
          HEROKU_API_KEY: ${{ secrets.HEROKU_API_KEY }}
        run: |
          heroku login
          heroku container:push web --app amadioha-cyber-defense
          heroku container:release web --app amadioha-cyber-defense
```

---

## 🆘 Troubleshooting

### Docker Issues

```bash
# Clear Docker cache
docker system prune

# View image layers
docker history amadioha-cyber-defense:latest

# Interactive shell
docker run -it amadioha-cyber-defense:latest /bin/bash
```

### Heroku Issues

```bash
# View app config
heroku config -a amadioha-cyber-defense

# Restart app
heroku restart -a amadioha-cyber-defense

# Clear buildpack cache
heroku builds:cache:purge -a amadioha-cyber-defense
```

### AWS EC2 Issues

```bash
# SSH with verbose logging
ssh -v -i your-key.pem ubuntu@your-instance-ip

# Check service status
systemctl status amadioha
journalctl -u amadioha -n 50 -f

# Test port 5000
curl -i http://localhost:5000/health
```

---

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Heroku Deployment](https://devcenter.heroku.com/)
- [AWS ECS Guide](https://docs.aws.amazon.com/ecs/)
- [Gunicorn Configuration](https://docs.gunicorn.org/)
- [Nginx Proxy Setup](https://nginx.org/docs/)
- [Let's Encrypt SSL](https://letsencrypt.org/getting-started/)

---

## 🎯 Recommended Deployment Path

For **fastest deployment**: → **Heroku** (1 command)
For **best control**: → **AWS EC2** with Nginx
For **scalability**: → **AWS ECS/Fargate**
For **learning**: → **Docker locally**, then EC2

---

**Happy deploying! 🚀**
