#!/bin/bash
set -e

echo "🧹 Cleaning up Mobile Security Platform from Minikube"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Delete all resources
print_status "Deleting Kubernetes resources..."
kubectl delete -f k8s/security-agent-deployment.yaml --ignore-not-found=true
kubectl delete -f k8s/mobsf-deployment.yaml --ignore-not-found=true
kubectl delete -f k8s/persistent-volumes.yaml --ignore-not-found=true
kubectl delete -f k8s/secrets-config.yaml --ignore-not-found=true
kubectl delete -f k8s/namespace.yaml --ignore-not-found=true

print_success "All resources deleted"

# Clean up Docker images (optional)
read -p "Do you want to remove Docker images? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Removing Docker images..."
    eval $(minikube docker-env)
    docker rmi mobile-security-agent:latest --force || true
    print_success "Docker images removed"
fi

print_success "Cleanup completed!"