# OpenZiti Tunneling Service - Setup Guide

This guide provides instructions for both local development and production deployment of the OpenZiti Tunneling Service.

## Table of Contents
1. [Local Development Setup](#1-local-development-setup)
2. [Production Deployment](#2-production-deployment)
3. [Common Operations](#3-common-operations)

## Prerequisites

- Docker (v20.10+) with Docker Compose
- Git (for development only)
- Minimum System Requirements:
  - 2 CPU cores
  - 4GB RAM (8GB recommended for production)
  - 10GB free disk space

# 1. Local Development Setup

This section covers setting up a development environment on your local machine.

## 1.1 Get the Source Code

```bash
git clone https://github.com/inviti8/hvym_tunnler.git
cd hvym_tunnler
```

## 1.2 Development Environment with Docker

All development happens inside containers. The following will set up:
- OpenZiti Controller
- OpenZiti Router
- PostgreSQL Database
- Development API Server
- Development Tools

## 1.3 Development Environment Setup

The repository includes a complete development environment with the OpenZiti Python SDK. The main components are:

- `app/` - Main application code
  - `services/` - Core services including Ziti tunnel management
  - `api/` - API endpoints and routes
  - `models/` - Data models and schemas
  - `utils/` - Utility functions
- `tests/` - Test files
- `requirements.txt` - Python dependencies
- `docker-compose.dev.yml` - Development Docker Compose configuration
- `Dockerfile.dev` - Development Dockerfile

### Project Structure

```
hvym_tunnler/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── services/
│   │   ├── __init__.py
│   │   └── ziti_service.py  # Ziti tunnel management
│   ├── api/
│   │   ├── __init__.py
│   │   └── v1/             # API version 1 endpoints
│   ├── models/
│   │   └── __init__.py
│   └── utils/
│       └── __init__.py
├── tests/                   # Test files
├── docker-compose.dev.yml   # Development compose file
├── Dockerfile.dev           # Development Dockerfile
└── requirements.txt         # Python dependencies
```

### Development Dockerfile

The `Dockerfile.dev` is used to build the development container with all necessary tools:

```dockerfile
# Use Python 3.9 base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user and switch to it
RUN useradd -m developer && \
    chown -R developer:developer /app
USER developer

# Command to keep container running
CMD ["tail", "-f", "/dev/null"]
```

### Development Docker Compose

The `docker-compose.dev.yml` file configures all necessary services for development. You can find it in the root of the repository.

## 1.4 Development Workflow

### Starting the Development Environment

1. **Create required directories**:
   ```bash
   mkdir -p ./data/{controller,router,postgres}
   chmod -R 777 ./data  # Adjust permissions as needed
   ```

2. **Start the development environment**:
   ```bash
   # Create the Docker network if it doesn't exist
   docker network create ziti || true
   
   # Build and start all services
   docker-compose -f docker-compose.dev.yml up -d --build
   
   # Enter the development container
   docker exec -it tunneler-dev bash
   ```

3. **Initialize OpenZiti**:
   ```bash
   # Inside the development container
   cd /app
   
   # Initialize the controller
   docker-compose -f docker-compose.dev.yml exec ziti-controller \
     /openziti/ziti-controller edge init /openziti/ziti-controller.yaml -u admin -p admin
   
   # Initialize the router
   docker-compose -f docker-compose.dev.yml exec ziti-router \
     /openziti/ziti-router init /openziti/ziti-router.yaml
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Start the development server**:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### API Documentation

Once the development server is running, you can access:

- **Interactive API Docs**: http://localhost:8000/docs
- **Alternative API Docs**: http://localhost:8000/redoc

### Testing the API

You can test the API using `curl` or any HTTP client:

```bash
# Create a new tunnel
curl -X POST "http://localhost:8000/tunnels/" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user1", "service_name": "webapp", "local_port": 3000}'

# List all tunnels
curl "http://localhost:8000/tunnels/"
```

### Running Tests

To run the test suite:

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run tests
pytest tests/
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code with black
black .

# Check code style with flake8
flake8 .

# Check type hints with mypy
mypy .

# Sort imports with isort
isort .
```

## 1.5 Development Tips

- The code is mounted in the container, so changes are reflected immediately
- Use `docker-compose -f docker-compose.dev.yml logs -f` to view logs
- The API will automatically reload when you make changes to the code

## 1.6 Verifying the Setup

```bash
# Inside the container
python --version
pip list
git --version
```

### 1.3 Install Additional Development Tools (Optional)

If you need additional tools, you can install them in the container:

```bash
# Example: Install development tools
sudo apt-get update && sudo apt-get install -y \
    htop \
    net-tools \
    dnsutils
```

### 1.4 Set Up Git (if needed)

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 1.5 Install Project Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# For development, install additional tools
pip install pytest pytest-cov black flake8 mypy
```

### 1.6 Verify the Development Environment

```bash
# Run basic checks
python -m pytest tests/
flake8 .
mypy .
```

# 2. Production Deployment

## 2.1 Server Requirements

- Linux-based OS (Ubuntu 20.04+ recommended)
- Docker and Docker Compose
- Public IP address with ports 80, 443, 1280, 3022, and 6262 open
- Domain name with DNS pointing to your server

## 2.2 Deployment Steps

1. **SSH into your VPS**:
   ```bash
   ssh user@your-vps-ip
   ```

2. **Install Docker and Docker Compose**:
   ```bash
   # For Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y docker.io docker-compose
   sudo systemctl enable --now docker
   sudo usermod -aG docker $USER
   ```

3. **Create deployment directory**:
   ```bash
   mkdir -p /opt/ziti-tunneler
   cd /opt/ziti-tunneler
   ```

4. **Create production docker-compose.yml**:
   ```yaml
   version: '3.8'
   
   services:
     ziti-controller:
       image: openziti/quickstart:latest
       container_name: ziti-controller
       restart: unless-stopped
       ports:
         - "1280:1280"
         - "6262:6262"
       environment:
         - ZITI_CTRL_EDGE_ADVERTISED_ADDRESS=your-domain.com
         - ZITI_CTRL_EDGE_ADVERTISED_PORT=1280
       volumes:
         - ./data/controller:/openziti
       networks:
         - ziti
   
     ziti-router:
       image: openziti/quickstart:latest
       container_name: ziti-router
       restart: unless-stopped
       ports:
         - "3022:3022"
       environment:
         - ZITI_ROUTER_NAME=edge-router
         - ZITI_CTRL_ENDPOINT=ziti-controller:6262
       volumes:
         - ./data/router:/openziti
       depends_on:
         - ziti-controller
       networks:
         - ziti
   
     tunnel-api:
       build: .
       container_name: tunnel-api
       restart: unless-stopped
       ports:
         - "8000:8000"
       environment:
         - DATABASE_URL=postgresql://postgres:${DB_PASSWORD}@postgres:5432/tunneldb
         - OPENZITI_CTRL_ENDPOINT=http://ziti-controller:1280
         - OPENZITI_USERNAME=admin
         - OPENZITI_PASSWORD=${ADMIN_PASSWORD}
       depends_on:
         - ziti-controller
         - postgres
       networks:
         - ziti
   
     postgres:
       image: postgres:14-alpine
       container_name: postgres
       environment:
         - POSTGRES_USER=postgres
         - POSTGRES_PASSWORD=${DB_PASSWORD}
         - POSTGRES_DB=tunneldb
       volumes:
         - ./data/postgres:/var/lib/postgresql/data
       networks:
         - ziti
   
   networks:
     ziti:
       driver: bridge
   ```

5. **Create .env file**:
   ```bash
   # Generate strong passwords
   echo "DB_PASSWORD=$(openssl rand -hex 16)" > .env
   echo "ADMIN_PASSWORD=$(openssl rand -hex 16)" >> .env
   ```

6. **Start the services**:
   ```bash
   docker-compose up -d
   ```

7. **Initialize OpenZiti**:
   ```bash
   # Initialize controller
   docker-compose exec ziti-controller /openziti/ziti-controller edge init /openziti/ziti-controller.yaml -u admin -p $ADMIN_PASSWORD
   
   # Initialize router
   docker-compose exec ziti-router /openziti/ziti-router init /openziti/ziti-router.yaml
   ```

# 3. Common Operations

## 3.1 Starting the Services

### Local Development
```bash
docker-compose -f docker-compose.dev.yml up -d
```

### Production
```bash
docker-compose up -d
```

## 3.2 Stopping Services

### Local Development
```bash
docker-compose -f docker-compose.dev.yml down
```

### Production
```bash
docker-compose down
```

## 3.3 Viewing Logs

### Application Logs
```bash
docker-compose logs -f tunnel-api
```

### OpenZiti Controller Logs
```bash
docker-compose logs -f ziti-controller
```

## 3.4 Backing Up Data

1. **Database Backup**:
   ```bash
   docker-compose exec -T postgres pg_dump -U postgres tunneldb > backup_$(date +%Y%m%d).sql
   ```

2. **OpenZiti Data**:
   ```bash
   tar czvf ziti_backup_$(date +%Y%m%d).tar.gz ./data
   ```

## 3.5 Upgrading

1. Pull the latest changes:
   ```bash
   git pull origin main  # For development
   ```

2. Rebuild and restart:
   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

## 3.6 Troubleshooting

### Common Issues

1. **Port Conflicts**:
   ```bash
   # Check for processes using a port
   sudo lsof -i :8000
   ```

2. **Container Not Starting**:
   ```bash
   # Check container logs
   docker-compose logs [service_name]
   
   # Check container status
   docker ps -a
   ```

3. **Network Issues**:
   ```bash
   # Check network configuration
   docker network inspect ziti
   ```

## 4. Security Considerations

1. **Firewall Configuration**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 80,443,1280,3022,6262/tcp
   sudo ufw enable
   ```

2. **SSL/TLS**:
   - Use a reverse proxy like Nginx with Let's Encrypt
   - Configure automatic certificate renewal

3. **Regular Updates**:
   - Keep Docker and all containers updated
   - Regularly update dependencies

## 5. Monitoring

1. **Container Health**:
   ```bash
   docker stats
   docker-compose ps
   ```

2. **Log Rotation**:
   Configure Docker daemon log rotation in `/etc/docker/daemon.json`:
   ```json
   {
     "log-driver": "json-file",
     "log-opts": {
       "max-size": "10m",
       "max-file": "3"
     }
   }
   ```

## 6. Support

For support, please:
1. Check the logs: `docker-compose logs`
2. Review the documentation
3. Open an issue on GitHub if needed

```yaml
version: '3.8'

services:
  # OpenZiti Controller
  ziti-controller:
    image: openziti/quickstart:latest
    container_name: ziti-controller
    restart: unless-stopped
    ports:
      - "1280:1280"  # Edge API
      - "6262:6262"  # Fabric API
    environment:
      - ZITI_CTRL_EDGE_ADVERTISED_ADDRESS=ziti-controller
      - ZITI_CTRL_EDGE_ADVERTISED_PORT=1280
    volumes:
      - ./data/controller:/openziti
    networks:
      - ziti
    networks:
      - ziti

  # OpenZiti Router
  ziti-router:
    image: openziti/quickstart:latest
    container_name: ziti-router
    restart: unless-stopped
    ports:
      - "3022:3022"  # Edge Router
    environment:
      - ZITI_ROUTER_NAME=ziti-router
      - ZITI_CTRL_ENDPOINT=ziti-controller:6262
    volumes:
      - ./data/router:/openziti
    depends_on:
      - ziti-controller
    networks:
      - ziti

  # PostgreSQL Database
  postgres:
    image: postgres:14-alpine
    container_name: postgres
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=tunneldb
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    networks:
      - ziti

networks:
  ziti:
    external: true

  # Management API (Development)
  tunnel-api:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: tunnel-api
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/tunneldb
      - OPENZITI_CTRL_ENDPOINT=http://ziti-controller:1280
      - OPENZITI_USERNAME=admin
      - OPENZITI_PASSWORD=admin
      - PYTHONPATH=/app
    depends_on:
      - ziti-controller
      - postgres
    volumes:
      - .:/app
      - /app/__pycache__
    networks:
      - ziti
    tty: true
    stdin_open: true

## 4. Start the Services

### 4.1 Start OpenZiti Services

First, start the OpenZiti infrastructure:

```bash
# Start OpenZiti services
docker-compose -f docker-compose.services.yml up -d

# Initialize the controller
docker-compose -f docker-compose.services.yml exec ziti-controller /openziti/ziti-controller edge init /openziti/ziti-controller.yaml -u admin -p admin

# Initialize the router
docker-compose -f docker-compose.services.yml exec ziti-router /openziti/ziti-router init /openziti/ziti-router.yaml
```

### 4.2 Start the Development Environment

In a new terminal, start the development environment:

```bash
# Build and start the development container
docker-compose -f docker-compose.dev.yml up -d --build

# Enter the development container
docker exec -it tunneler-dev bash

# Inside the container, start the development server
cd /app
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

## 5. Access the Services

- **API Documentation**: http://localhost:8000/docs
- **OpenZiti Controller**: http://localhost:1280
- **PostgreSQL**:
  - Host: postgres
  - Port: 5432
  - Database: tunneldb
  - Username: postgres
  - Password: password

## 6. Development Workflow

### 6.1 Running Tests

```bash
# Run tests
docker-compose -f docker-compose.dev.yml exec tunneler-dev pytest tests/

# Run with coverage
docker-compose -f docker-compose.dev.yml exec tunneler-dev pytest --cov=app tests/
```

### 6.2 Code Quality Checks

```bash
# Run flake8
docker-compose -f docker-compose.dev.yml exec tunneler-dev flake8 .

# Run mypy
docker-compose -f docker-compose.dev.yml exec tunneler-dev mypy .

# Format code with black
docker-compose -f docker-compose.dev.yml exec tunneler-dev black .
```

## 7. Managing the Environment

### 7.1 Stop All Services

```bash
# Stop development container
docker-compose -f docker-compose.dev.yml down

# Stop OpenZiti services
docker-compose -f docker-compose.services.yml down
```

### 7.2 Reset the Environment

To completely reset the development environment:

```bash
# Stop and remove all containers
docker-compose -f docker-compose.dev.yml -f docker-compose.services.yml down -v

# Remove the Docker network
docker network rm ziti

# Remove all Docker volumes
docker volume prune -f

# Remove the data directory (WARNING: This will delete all data)
sudo rm -rf ./data
```

## 8. Production Considerations

For production deployment, consider the following:
```

## 4. Create Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
# Use Python 3.9 slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 5. Build and Start Services

### 5.1 Build the Docker images

```bash
docker-compose build
```

### 5.2 Start the services

```bash
docker-compose up -d
```

### 5.3 Check the logs

```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f tunnel-api
```

## 6. Initialize OpenZiti

### 6.1 Initialize the controller

```bash
docker-compose exec ziti-controller /openziti/ziti-controller edge init /openziti/ziti-controller.yaml -u admin -p admin
```

### 6.2 Initialize the router

```bash
docker-compose exec ziti-router /openziti/ziti-router init /openziti/ziti-router.yaml
```

## 7. Test the Setup

### 7.1 Check service status

```bash
# List running containers
docker-compose ps

# Check API health
curl http://localhost:8000/health
```

### 7.2 Create a test tunnel

```bash
# Install the client locally
pip install -e .

# Create a test tunnel (replace with actual credentials)
ziti-tunnel login admin admin
ziti-tunnel create 8080 test-service
```

## 8. Updating the Service

### 8.1 Rebuild and restart after changes

```bash
# Rebuild the API container
docker-compose build tunnel-api

# Restart the service
docker-compose up -d --no-deps tunnel-api
```

### 8.2 View logs

```bash
docker-compose logs -f tunnel-api
```

## 9. Troubleshooting

### 9.1 Common Issues

1. **Port conflicts**: Ensure ports 1280, 6262, 3022, and 8000 are available
   ```bash
   # Check for processes using specific ports
   sudo lsof -i :1280
   ```

2. **Permission issues**: If you see permission denied errors, adjust the data directory permissions
   ```bash
   sudo chown -R $USER:$USER ./data
   ```

3. **Container not starting**: Check the logs for errors
   ```bash
   docker-compose logs tunnel-api
   ```

### 9.2 Resetting the Environment

To completely reset the environment:

```bash
# Stop and remove all containers
docker-compose down -v

# Remove the network
docker network rm ziti

# Remove all Docker volumes
docker volume prune -f

# Remove the data directory (WARNING: This will delete all data)
sudo rm -rf ./data
```

## 10. Development Workflow

### 10.1 Running Tests

```bash
# Run tests inside the container
docker-compose exec tunnel-api python -m pytest tests/
```

### 10.2 Accessing the Database

```bash
# Connect to the PostgreSQL database
docker-compose exec postgres psql -U postgres -d tunneldb
```

### 10.3 Viewing API Documentation

Once the service is running, access the API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 11. Production Considerations

For production deployment, consider:

1. Using environment variables for sensitive data
2. Setting up proper TLS/SSL termination
3. Implementing proper backup strategies
4. Setting up monitoring and alerting
5. Configuring proper logging and log rotation
6. Implementing rate limiting and request validation

## 12. Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## License

[Your License Here]
