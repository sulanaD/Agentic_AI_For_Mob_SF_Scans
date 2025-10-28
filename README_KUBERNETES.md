# Kubernetes Deployment Guide

This guide explains how to deploy the Mobile Security Platform to Kubernetes, specifically tested with Minikube.

## Architecture Overview

The platform consists of two main components:
- **MobSF Pod**: Runs the Mobile Security Framework for APK scanning
- **Security Agent Pod**: Runs our AI-powered security analysis agent

Both pods communicate through Kubernetes services and share persistent storage for scan results.

## Prerequisites

1. **Minikube** installed and running
2. **kubectl** configured to work with your Minikube cluster
3. **Docker** installed
4. **API Keys** for Groq AI service

## Quick Start

### 1. Start Minikube (if not running)
```bash
minikube start
```

### 2. Configure API Keys
Edit `k8s/secrets-config.yaml` and add your base64-encoded API keys:

```bash
# Encode your Groq API key
echo -n "your-groq-api-key" | base64

# Add the result to secrets-config.yaml
```

### 3. Deploy the Platform
```bash
./deploy.sh
```

### 4. Access the Services
The deployment script will output the URLs for both services:
- MobSF API: `http://minikube-ip:port`
- Security Agent API: `http://minikube-ip:port`

## Manual Deployment Steps

If you prefer to deploy manually:

### 1. Build the Docker Image
```bash
# Set Docker environment to use Minikube's Docker daemon
eval $(minikube docker-env)

# Build the image
docker build -t mobile-security-agent:latest .
```

### 2. Apply Kubernetes Manifests
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets-config.yaml
kubectl apply -f k8s/persistent-volumes.yaml
kubectl apply -f k8s/mobsf-deployment.yaml
kubectl apply -f k8s/security-agent-deployment.yaml
```

### 3. Wait for Deployment
```bash
kubectl wait --for=condition=available --timeout=300s deployment/mobsf-deployment -n mobile-security
kubectl wait --for=condition=available --timeout=300s deployment/security-agent-deployment -n mobile-security
```

### 4. Get Service URLs
```bash
minikube service list -n mobile-security
```

## Service Endpoints

### Security Agent API

- **Health Check**: `GET /health`
- **Configuration**: `GET /config`
- **Scan APK**: `POST /scan`
  - Form data: `file` (APK file)
  - Optional: `analysis_type` (basic|full)

### Example API Usage

```bash
# Health check
curl http://agent-url/health

# Scan an APK
curl -X POST \
  -F "file=@your-app.apk" \
  -F "analysis_type=full" \
  http://agent-url/scan
```

## Storage

The platform uses persistent volumes for:
- **MobSF Data**: Stores MobSF configuration and scan data
- **Agent Outputs**: Stores raw scan outputs
- **Agent Reports**: Stores generated reports

## Monitoring

### View Pod Status
```bash
kubectl get pods -n mobile-security
```

### View Logs
```bash
# Security Agent logs
kubectl logs -f deployment/security-agent-deployment -n mobile-security

# MobSF logs
kubectl logs -f deployment/mobsf-deployment -n mobile-security
```

### Access Kubernetes Dashboard
```bash
minikube dashboard
```

## Scaling

To scale the security agent:
```bash
kubectl scale deployment security-agent-deployment --replicas=3 -n mobile-security
```

Note: MobSF should typically run as a single instance due to its stateful nature.

## Troubleshooting

### Common Issues

1. **Image Pull Errors**
   - Ensure you're using Minikube's Docker daemon: `eval $(minikube docker-env)`
   - Check if image exists: `docker images | grep mobile-security-agent`

2. **Pod Startup Issues**
   - Check pod events: `kubectl describe pod <pod-name> -n mobile-security`
   - Verify resource limits and requests

3. **Service Communication Issues**
   - Verify services: `kubectl get services -n mobile-security`
   - Check DNS resolution: `nslookup mobsf-service.mobile-security.svc.cluster.local`

4. **Storage Issues**
   - Check PVC status: `kubectl get pvc -n mobile-security`
   - Verify storage class: `kubectl get storageclass`

### Debug Commands

```bash
# Get all resources in namespace
kubectl get all -n mobile-security

# Describe problematic pod
kubectl describe pod <pod-name> -n mobile-security

# Get detailed events
kubectl get events -n mobile-security --sort-by='.lastTimestamp'

# Execute into pod for debugging
kubectl exec -it deployment/security-agent-deployment -n mobile-security -- /bin/bash
```

## Cleanup

To remove the entire deployment:
```bash
./cleanup.sh
```

Or manually:
```bash
kubectl delete namespace mobile-security
```

## Production Considerations

For production deployment, consider:

1. **Resource Limits**: Adjust CPU/memory limits based on workload
2. **Security**: 
   - Use proper secrets management (e.g., external secret operators)
   - Enable RBAC
   - Use security contexts
3. **Storage**: Use appropriate storage classes for your environment
4. **Monitoring**: Add proper monitoring and alerting
5. **Backup**: Implement backup strategies for persistent data
6. **Load Balancing**: Use proper ingress controllers for external access

## Development

For development with live code updates:
```bash
docker-compose -f docker-compose.dev.yml up
```

This mounts the source code as a volume for faster development cycles.