# Docker Deployment Guide

This guide explains how to deploy the Mobile Security Analysis platform using Docker.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM available for containers
- At least 10GB disk space

## Quick Start

1. **Clone and navigate to the project**:
   ```bash
   git clone <repository-url>
   cd Agentic_AI_For_Mob_SF_Scans
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.docker .env
   # Edit .env with your API keys
   nano .env
   ```

3. **Start all services**:
   ```bash
   docker-compose up -d
   ```

4. **Access the application**:
   - Frontend: http://localhost
   - Backend API: http://localhost:8081
   - MobSF: http://localhost:8000

## Architecture

The Docker setup includes three main services:

### 1. MobSF Service (`mobsf`)
- **Image**: `opensecurity/mobsf:latest`
- **Port**: 8000
- **Purpose**: Mobile security framework for APK analysis
- **Volumes**: Persistent data storage for scan results

### 2. Backend Service (`backend`)
- **Build**: Custom Python 3.11 image
- **Port**: 8081
- **Purpose**: FastAPI server with AI analysis capabilities
- **Dependencies**: MobSF service
- **Volumes**: Logs, reports, and checkpoints

### 3. Frontend Service (`frontend`)
- **Build**: Multi-stage React + Nginx image
- **Port**: 80
- **Purpose**: Web interface for file uploads and results
- **Dependencies**: Backend service
- **Features**: Nginx proxy for API calls

## Configuration

### Environment Variables

Required variables in `.env`:

```bash
# MobSF Configuration
MOBSF_API_KEY=your_mobsf_api_key

# AI Provider (choose one)
GROQ_API_KEY=your_groq_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key

# AI Settings
AI_PROVIDER=groq
AI_MODEL_NAME=llama-3.3-70b-versatile
```

### Network Configuration

All services run on a custom bridge network (`app-network`) for secure inter-service communication.

## Commands

### Start Services
```bash
# Start all services in background
docker-compose up -d

# Start with logs visible
docker-compose up

# Start specific service
docker-compose up backend
```

### Stop Services
```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### View Logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs backend

# Follow logs
docker-compose logs -f frontend
```

### Scale Services
```bash
# Scale backend to 2 instances
docker-compose up --scale backend=2
```

## Health Checks

All services include health checks:

- **MobSF**: Checks API availability
- **Backend**: Validates FastAPI health endpoint
- **Frontend**: Confirms Nginx is serving content

View health status:
```bash
docker-compose ps
```

## Volumes

Persistent data is stored in named volumes:

- `mobsf_data`: MobSF scan data and configuration
- `backend_logs`: Application logs
- `backend_reports`: Generated security reports

## Troubleshooting

### Common Issues

1. **Port conflicts**:
   ```bash
   # Check for conflicting processes
   sudo lsof -i :80
   sudo lsof -i :8000
   sudo lsof -i :8081
   ```

2. **Memory issues**:
   ```bash
   # Check available memory
   docker system df
   docker system prune
   ```

3. **Build failures**:
   ```bash
   # Rebuild without cache
   docker-compose build --no-cache
   ```

4. **API key issues**:
   ```bash
   # Verify environment variables
   docker-compose config
   ```

### View Service Status
```bash
# Check all services
docker-compose ps

# Inspect specific service
docker inspect mobile-security-backend
```

### Access Container Shells
```bash
# Backend container
docker exec -it mobile-security-backend bash

# Frontend container
docker exec -it mobile-security-frontend sh

# MobSF container
docker exec -it mobsf bash
```

## Development

For development with hot reloading:

1. **Backend development**:
   ```bash
   # Override with volume mount
   docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
   ```

2. **Frontend development**:
   ```bash
   # Run frontend locally, backend in Docker
   docker-compose up mobsf backend
   cd frontend && npm start
   ```

## Production Deployment

For production deployment:

1. **Use specific image tags**:
   ```yaml
   image: your-registry/mobile-security-backend:v1.0.0
   ```

2. **Add resource limits**:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 2G
         cpus: '1.0'
   ```

3. **Configure reverse proxy** (Nginx/Traefik)
4. **Set up SSL certificates**
5. **Configure log aggregation**
6. **Set up monitoring and alerts**

## Security Considerations

- API keys are passed as environment variables
- Services run with non-root users
- Inter-service communication uses private network
- Volumes have restricted access
- Health checks prevent unhealthy deployments

## Monitoring

Monitor the deployment:

```bash
# Resource usage
docker stats

# System events
docker events

# Service logs
docker-compose logs -f --tail=100
```