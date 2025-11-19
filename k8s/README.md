# FastGate Kubernetes Deployment

This directory contains production-ready Kubernetes manifests for deploying FastGate.

## Directory Structure

```
k8s/
├── base/                      # Base manifests (environment-agnostic)
│   ├── deployment.yaml        # Main FastGate deployment
│   ├── service.yaml           # LoadBalancer and headless services
│   ├── configmap.yaml         # Application configuration
│   ├── secret.yaml            # Secrets template
│   ├── serviceaccount.yaml    # RBAC configuration
│   ├── hpa.yaml               # Horizontal Pod Autoscaler
│   ├── servicemonitor.yaml    # Prometheus monitoring
│   ├── networkpolicy.yaml     # Network security policies
│   ├── poddisruptionbudget.yaml # High availability
│   ├── ingress.yaml           # Ingress configuration
│   └── kustomization.yaml     # Kustomize base
└── overlays/
    ├── production/            # Production overrides
    │   └── kustomization.yaml
    └── development/           # Development overrides
        └── kustomization.yaml
```

## Prerequisites

- Kubernetes 1.24+ cluster
- `kubectl` CLI tool
- `kustomize` 4.5+ (or `kubectl` with built-in kustomize)
- Container registry access (to push FastGate image)
- (Optional) Prometheus Operator for monitoring
- (Optional) cert-manager for TLS certificates

## Quick Start

### 1. Build and Push Docker Image

```bash
# Build FastGate Docker image
docker build -t your-registry/fastgate:v1.0.0 .

# Push to registry
docker push your-registry/fastgate:v1.0.0
```

### 2. Generate Secrets

```bash
# Generate production secrets
kubectl create namespace production

kubectl create secret generic fastgate-secrets \
  --namespace=production \
  --from-literal=token-secret=$(openssl rand -base64 32) \
  --from-literal=cluster-secret=$(openssl rand -base64 32)

# Create TLS certificate secret
kubectl create secret tls fastgate-tls \
  --namespace=production \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

### 3. Update Configuration

Edit `base/configmap.yaml`:
```yaml
# Update these values for your environment:
webauthn:
  rp_id: "your-domain.com"
  rp_origins:
    - "https://your-domain.com"

proxy:
  origin: "http://your-backend-service:8080"

server:
  trusted_proxies:
    - "10.0.0.0/8"  # Your VPC CIDR
```

### 4. Update Kustomization

Edit `overlays/production/kustomization.yaml`:
```yaml
images:
  - name: fastgate
    newName: your-registry/fastgate
    newTag: v1.0.0  # Your image tag
```

### 5. Deploy to Production

```bash
# Preview what will be deployed
kubectl kustomize overlays/production

# Apply to cluster
kubectl apply -k overlays/production

# Watch rollout
kubectl rollout status deployment/fastgate -n production
```

## Deployment Validation

### Check Pod Status

```bash
kubectl get pods -n production -l app=fastgate
kubectl logs -n production -l app=fastgate --tail=100
```

### Check Service

```bash
kubectl get svc -n production fastgate
kubectl get endpoints -n production fastgate
```

### Check Health

```bash
POD=$(kubectl get pod -n production -l app=fastgate -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n production $POD -- wget -qO- http://localhost:8080/healthz
```

### Check Metrics

```bash
kubectl port-forward -n production svc/fastgate 8080:80
curl http://localhost:8080/metrics
```

## Scaling

### Manual Scaling

```bash
# Scale to 10 replicas
kubectl scale deployment/fastgate -n production --replicas=10
```

### Horizontal Pod Autoscaler

The HPA is pre-configured and will automatically scale between 5-50 pods based on:
- CPU utilization (target: 70%)
- Memory utilization (target: 80%)

View HPA status:
```bash
kubectl get hpa -n production fastgate
kubectl describe hpa -n production fastgate
```

## Monitoring

### Prometheus Metrics

FastGate exposes metrics at `/metrics`:
- `fastgate_authz_decision_total` - Authorization decisions
- `fastgate_challenge_started_total` - Challenges issued
- `fastgate_challenge_solved_total` - Challenges solved
- `fastgate_rate_limit_hits_total` - Rate limit violations
- `fastgate_proxy_errors_total` - Proxy errors
- `fastgate_webauthn_attestation_total` - WebAuthn results

### Grafana Dashboard

Import the included dashboard (coming soon) or create custom dashboards using the metrics.

### Alerts

Pre-configured PrometheusRules in `servicemonitor.yaml`:
- `FastGateHighRateLimitHits` - Potential attack detected
- `FastGateHighBlockRate` - High block rate
- `FastGateHighProxyErrors` - Backend issues
- `FastGateWebAuthnFailures` - Auth failures

## Configuration Management

### Update ConfigMap

```bash
# Edit configmap
kubectl edit configmap -n production fastgate-config

# Or apply changes
kubectl apply -k overlays/production

# Restart pods to pick up changes
kubectl rollout restart deployment/fastgate -n production
```

### Rotate Secrets

```bash
# Generate new secrets
NEW_TOKEN=$(openssl rand -base64 32)
NEW_CLUSTER=$(openssl rand -base64 32)

# Update secret
kubectl create secret generic fastgate-secrets \
  --namespace=production \
  --from-literal=token-secret=$NEW_TOKEN \
  --from-literal=cluster-secret=$NEW_CLUSTER \
  --dry-run=client -o yaml | kubectl apply -f -

# Rolling restart
kubectl rollout restart deployment/fastgate -n production
```

## Troubleshooting

### Pod Crashes (CrashLoopBackOff)

```bash
# Check logs
kubectl logs -n production -l app=fastgate --previous

# Check events
kubectl get events -n production --sort-by='.lastTimestamp'

# Describe pod
kubectl describe pod -n production <pod-name>
```

Common issues:
1. **Test key validation error**: Ensure `FASTGATE_ALLOW_TEST_KEYS` is NOT set in production
2. **Config validation fails**: Check ConfigMap syntax
3. **Secret not found**: Ensure secrets are created in correct namespace

### High Memory Usage

```bash
# Check memory usage
kubectl top pods -n production -l app=fastgate

# Check for memory leaks (enable profiling)
kubectl port-forward -n production svc/fastgate 6060:8080
go tool pprof http://localhost:6060/debug/pprof/heap
```

### Connectivity Issues

```bash
# Test from within cluster
kubectl run -n production test-pod --rm -it --image=curlimages/curl -- \
  curl -v http://fastgate/healthz

# Check network policies
kubectl get networkpolicy -n production
```

## Security Hardening

### Enable Pod Security Standards

```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

### Network Policies

The included `networkpolicy.yaml` restricts:
- Ingress: Only from load balancer and Prometheus
- Egress: Only to backend, DNS, and other FastGate pods

Customize for your environment.

### Resource Quotas

```bash
kubectl create quota fastgate-quota \
  --namespace=production \
  --hard=cpu=20,memory=40Gi,pods=50
```

## Maintenance

### Rolling Update

```bash
# Update image
kubectl set image deployment/fastgate \
  -n production \
  fastgate=your-registry/fastgate:v1.1.0

# Monitor rollout
kubectl rollout status deployment/fastgate -n production

# Rollback if needed
kubectl rollout undo deployment/fastgate -n production
```

### Backup Configuration

```bash
# Export all resources
kubectl get all,configmap,secret,ingress -n production -o yaml > backup.yaml
```

## Development Environment

Deploy to development namespace with lower resources:

```bash
kubectl create namespace development

# Deploy with development overlay
kubectl apply -k overlays/development

# Port forward for local testing
kubectl port-forward -n development svc/fastgate 8080:80
```

## Production Checklist

Before going to production, ensure:

- [ ] Secrets generated with `openssl rand -base64 32`
- [ ] TLS certificates configured
- [ ] `trusted_proxies` set to load balancer CIDRs
- [ ] `webauthn.rp_id` matches your domain
- [ ] `webauthn.rp_origins` uses HTTPS
- [ ] Backend service is accessible
- [ ] Resource limits appropriate for load
- [ ] HPA configured for expected traffic
- [ ] Monitoring and alerts configured
- [ ] Network policies reviewed
- [ ] PodDisruptionBudget ensures HA
- [ ] Image tag is pinned (not `latest`)
- [ ] `FASTGATE_ALLOW_TEST_KEYS` is NOT set

## Support

For issues or questions:
- Check logs: `kubectl logs -n production -l app=fastgate`
- Review SECURITY.md for security best practices
- Check configuration validation: See error messages
- Consult Kubernetes events: `kubectl get events -n production`
