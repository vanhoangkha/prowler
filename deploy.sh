#!/usr/bin/env bash
# deploy.sh — Deploy Prowler CNAPP to Kubernetes via Helm
set -euo pipefail

NAMESPACE="${NAMESPACE:-prowler}"
RELEASE="${RELEASE:-prowler-cnapp}"
CHART_DIR="$(dirname "$0")/kubernetes/helm"
VALUES="${VALUES:-$CHART_DIR/values.yaml}"

echo "═══════════════════════════════════════════"
echo " Prowler CNAPP — Kubernetes Deployment"
echo "═══════════════════════════════════════════"
echo ""
echo "  Namespace: $NAMESPACE"
echo "  Release:   $RELEASE"
echo "  Values:    $VALUES"
echo ""

# Pre-flight checks
echo "▸ Pre-flight checks"
kubectl cluster-info > /dev/null 2>&1 || { echo "  ✗ No K8s cluster access"; exit 1; }
echo "  ✓ Cluster accessible"
helm version > /dev/null 2>&1 || { echo "  ✗ Helm not installed"; exit 1; }
echo "  ✓ Helm available"
echo ""

# Create namespace
echo "▸ Creating namespace"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
echo ""

# Create secrets (if not exist)
echo "▸ Checking secrets"
if ! kubectl get secret prowler-db-secret -n "$NAMESPACE" > /dev/null 2>&1; then
    echo "  ⚠ Creating default DB secret (change in production!)"
    kubectl create secret generic prowler-db-secret \
        --from-literal=postgres-password=prowler-secret-pw \
        -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
fi

if ! kubectl get secret prowler-neo4j-secret -n "$NAMESPACE" > /dev/null 2>&1; then
    echo "  ⚠ Creating default Neo4j secret (change in production!)"
    kubectl create secret generic prowler-neo4j-secret \
        --from-literal=neo4j-password=neo4j-secret-pw \
        -n "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
fi
echo ""

# Deploy
echo "▸ Deploying Helm chart"
helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$NAMESPACE" \
    --values "$VALUES" \
    --wait \
    --timeout 10m

echo ""
echo "═══════════════════════════════════════════"
echo " ✓ Deployment complete!"
echo ""
echo " Access:"
echo "   kubectl port-forward svc/$RELEASE-prowler-cnapp-ui 3000:3000 -n $NAMESPACE"
echo "   kubectl port-forward svc/$RELEASE-prowler-cnapp-api 8080:8080 -n $NAMESPACE"
echo ""
echo " Status:"
echo "   kubectl get pods -n $NAMESPACE"
echo "   helm status $RELEASE -n $NAMESPACE"
echo "═══════════════════════════════════════════"
