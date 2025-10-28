#!/bin/bash
set -e

echo "🚀 Deploying Mobile Security Platform to Minikube"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Minikube is running
print_status "Checking Minikube status..."
if ! minikube status &> /dev/null; then
    print_error "Minikube is not running. Please start it with: minikube start"
    exit 1
fi
print_success "Minikube is running"

# Set Docker environment to use Minikube's Docker daemon
print_status "Setting Docker environment for Minikube..."
eval $(minikube docker-env)

# Build the Docker image
print_status "Building mobile security agent Docker image..."
docker build -t mobile-security-agent:latest .
print_success "Docker image built successfully"

# Create namespace
print_status "Creating namespace..."
kubectl apply -f k8s/namespace.yaml
print_success "Namespace created"

# Check if secrets exist, if not create empty ones
print_status "Checking secrets..."
if ! kubectl get secret mobile-security-secrets -n mobile-security &> /dev/null; then
    print_warning "Secrets not found. Creating empty secrets..."
    print_warning "Please update k8s/secrets-config.yaml with your API keys before deployment"
fi

# Apply all Kubernetes manifests
print_status "Applying Kubernetes manifests..."
kubectl apply -f k8s/secrets-config.yaml
kubectl apply -f k8s/persistent-volumes.yaml
kubectl apply -f k8s/mobsf-deployment.yaml
kubectl apply -f k8s/security-agent-deployment.yaml

print_success "All manifests applied"

# Wait for deployments to be ready
print_status "Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/mobsf-deployment -n mobile-security
kubectl wait --for=condition=available --timeout=300s deployment/security-agent-deployment -n mobile-security

print_success "Deployments are ready"

# Get service URLs
print_status "Getting service URLs..."
MOBSF_URL=$(minikube service mobsf-service -n mobile-security --url)
AGENT_URL=$(minikube service security-agent-service -n mobile-security --url)

print_success "Deployment completed successfully!"
echo ""
echo "📱 MobSF URL: $MOBSF_URL"
echo "🤖 Security Agent URL: $AGENT_URL"
echo ""
echo "📋 Quick commands:"
echo "  View pods: kubectl get pods -n mobile-security"
echo "  View services: kubectl get services -n mobile-security"
echo "  View logs: kubectl logs -f deployment/security-agent-deployment -n mobile-security"
echo "  Open dashboard: minikube dashboard"
echo ""
echo "🧪 Test the API:"
echo "  curl $AGENT_URL/health"
echo "  curl $AGENT_URL/config"