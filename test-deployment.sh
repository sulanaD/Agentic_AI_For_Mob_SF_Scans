#!/bin/bash

# Test script for the deployed Mobile Security Platform
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

echo "🧪 Testing Mobile Security Platform Deployment"
echo "=============================================="

# Get service URLs
print_status "Getting service URLs..."
AGENT_URL=$(minikube service security-agent-service -n mobile-security --url 2>/dev/null)
MOBSF_URL=$(minikube service mobsf-service -n mobile-security --url 2>/dev/null)

if [ -z "$AGENT_URL" ] || [ -z "$MOBSF_URL" ]; then
    print_error "Failed to get service URLs. Is the deployment running?"
    exit 1
fi

print_info "Agent URL: $AGENT_URL"
print_info "MobSF URL: $MOBSF_URL"
echo ""

# Test 1: Check if services are responding
print_status "Testing service health..."

# Test Agent health endpoint
if curl -s -f "$AGENT_URL/health" > /dev/null; then
    print_success "Security Agent health check passed"
else
    print_error "Security Agent health check failed"
fi

# Test MobSF API docs
if curl -s -f "$MOBSF_URL/api_docs" > /dev/null; then
    print_success "MobSF API docs accessible"
else
    print_error "MobSF API docs not accessible"
fi

# Test 2: Check Agent configuration
print_status "Testing agent configuration..."
CONFIG_RESPONSE=$(curl -s "$AGENT_URL/config" || echo "")
if [ ! -z "$CONFIG_RESPONSE" ]; then
    print_success "Agent configuration retrieved"
    echo "$CONFIG_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$CONFIG_RESPONSE"
else
    print_error "Failed to retrieve agent configuration"
fi

echo ""

# Test 3: Check Kubernetes resources
print_status "Checking Kubernetes resources..."

# Check pods
PODS=$(kubectl get pods -n mobile-security --no-headers 2>/dev/null | wc -l)
RUNNING_PODS=$(kubectl get pods -n mobile-security --no-headers 2>/dev/null | grep "Running" | wc -l)

if [ "$PODS" -eq "$RUNNING_PODS" ] && [ "$PODS" -gt 0 ]; then
    print_success "All pods are running ($RUNNING_PODS/$PODS)"
else
    print_error "Some pods are not running ($RUNNING_PODS/$PODS)"
    kubectl get pods -n mobile-security
fi

# Check services
SERVICES=$(kubectl get services -n mobile-security --no-headers 2>/dev/null | wc -l)
if [ "$SERVICES" -gt 0 ]; then
    print_success "Services are configured ($SERVICES found)"
else
    print_error "No services found"
fi

# Check PVCs
PVCS=$(kubectl get pvc -n mobile-security --no-headers 2>/dev/null | grep "Bound" | wc -l)
if [ "$PVCS" -gt 0 ]; then
    print_success "Persistent volumes are bound ($PVCS found)"
else
    print_error "No bound persistent volumes found"
fi

echo ""

# Test 4: Sample APK scan (if test APK exists)
if [ -f "Test_11.8.5.apk" ]; then
    print_status "Testing APK scan with Test_11.8.5.apk..."
    
    SCAN_RESPONSE=$(curl -s -X POST \
        -F "file=@Test_11.8.5.apk" \
        -F "analysis_type=basic" \
        "$AGENT_URL/scan" 2>/dev/null || echo "")
    
    if echo "$SCAN_RESPONSE" | grep -q "success"; then
        print_success "APK scan completed successfully"
    else
        print_error "APK scan failed"
        echo "Response: $SCAN_RESPONSE"
    fi
else
    print_info "Test APK not found, skipping scan test"
fi

echo ""
echo "🏁 Test Summary"
echo "==============="
print_info "Platform is deployed and accessible at:"
print_info "  Security Agent: $AGENT_URL"
print_info "  MobSF: $MOBSF_URL"
echo ""
print_info "Useful commands:"
print_info "  kubectl get pods -n mobile-security"
print_info "  kubectl logs -f deployment/security-agent-deployment -n mobile-security"
print_info "  minikube dashboard"