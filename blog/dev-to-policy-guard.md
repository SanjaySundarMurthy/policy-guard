---
title: "I Built a CLI That Found 89 Security Violations in a 'Production-Ready' Kubernetes Cluster"
published: true
description: "policy-guard: A Kubernetes manifest security auditor with 50+ rules for Pod Security Standards, CIS benchmarks, and RBAC. Because kubectl apply -f yolo.yaml shouldn't be your deployment strategy."
tags: kubernetes, security, devops, opensource
cover_image: ""
---

## The YAML That Ruined My Weekend

Here's a true story. A senior engineer — let's call him Dave — deployed this to production on a Friday afternoon:

```yaml
containers:
- name: payment-processor
  image: company-registry.io/payments:latest
  securityContext:
    privileged: true
    runAsUser: 0
  env:
  - name: DB_PASSWORD
    value: "super-secret-p4ssw0rd!"
```

Privileged container. Running as root. Database password hardcoded in plaintext. Image using `:latest` tag from a private registry with no pull secrets.

Dave's PR had 3 approvals.

That's when I realized: **we don't have a code review problem. We have a "nobody can read YAML fast enough to catch everything" problem.**

So I built **policy-guard**.

---

## What Is policy-guard?

**policy-guard** is a CLI that audits your Kubernetes YAML manifests against:

- **Pod Security Standards** (Privileged, Baseline, Restricted)
- **CIS Kubernetes Benchmarks**
- **RBAC best practices** (wildcard permissions, cluster-admin abuse)
- **Container security** (image tags, probes, resources, secrets in env vars)
- **Network exposure** (LoadBalancer, NodePort, Ingress TLS)

50+ validation rules. No cluster needed. Runs anywhere Python does.

```bash
pip install policy-guard
policy-guard demo  # Watch it shred a sample cluster
```

**GitHub:** [github.com/SanjaySundarMurthy/policy-guard](https://github.com/SanjaySundarMurthy/policy-guard)

---

## The Demo: 89 Violations in 11 Resources

Run `policy-guard demo` and it creates a realistic "production" cluster with 6 manifest files. Here's what it finds:

```
Security Score: 0 / 100    Grade: F
Pod Security Standards — Compliant Level: PRIVILEGED
Violations: 89 total
  🔴 CRITICAL:  7
  🟠 HIGH:     29
  🟡 MEDIUM:   38
  🔵 LOW:       8
  ⚪ INFO:      7
```

**Grade F. Compliant at PRIVILEGED level.** That means literally nothing is restricted. Let's look at why.

---

## The Greatest Hits of Kubernetes Security Failures

### 1. "The Privileged Container" — PG-PSS-001

```yaml
securityContext:
  privileged: true
```

```
🔴 CRITICAL | PG-PSS-001 | Container 'payment' runs as privileged
```

A privileged container has full access to the host. It can see all processes, mount any filesystem, load kernel modules, and essentially become root on the node. It's not a container anymore — it's a suggestion.

**Fix:**
```yaml
securityContext:
  privileged: false
```

### 2. "I Am Root" — PG-PSS-009 + PG-PSS-010

```yaml
securityContext:
  runAsUser: 0  # root!
```

```
🟠 HIGH | PG-PSS-010 | Container 'payment' runs as UID 0 (root)
🟠 HIGH | PG-PSS-009 | Container 'payment' may run as root (runAsNonRoot not set)
```

Running as root inside a container is dangerous because container escapes exist. If an attacker breaks out of a container running as UID 0, they're root on the host.

**Fix:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
```

### 3. "The Docker Socket Mount" — PG-PSS-005

```yaml
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock
```

```
🔴 CRITICAL | PG-PSS-005 | Volume 'docker-sock' mounts hostPath '/var/run/docker.sock'
```

Mounting the Docker socket gives the container complete control over the container runtime. It can create new privileged containers, access other containers' filesystems, and essentially own the entire node. This is game over.

### 4. "Secrets in Environment Variables" — PG-CTR-007

```yaml
env:
- name: DB_PASSWORD
  value: "super-secret-p4ssw0rd!"
- name: API_KEY
  value: "sk_live_abc123xyz"
```

```
🟠 HIGH | PG-CTR-007 | Container 'payment' has potential secret in env var 'DB_PASSWORD'
🟠 HIGH | PG-CTR-007 | Container 'payment' has potential secret in env var 'API_KEY'
```

Environment variables are visible in `kubectl describe pod`, in pod logs, in crash dumps, and in any process that can read `/proc/*/environ`. Never put secrets in env vars — use Kubernetes Secrets or external secret managers.

### 5. "ClusterRole: God Mode" — PG-RBAC-007

```yaml
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

```
🔴 CRITICAL | PG-RBAC-007 | ClusterRole 'super-admin' is cluster-admin equivalent
```

`*.*.*` — this ClusterRole can do anything to anything in any namespace. Combined with a binding to `system:authenticated`:

```
🟠 HIGH | PG-RBAC-011 | Binding grants permissions to 'system:authenticated' group
🔴 CRITICAL | PG-RBAC-010 | Binding grants cluster-admin privileges
```

That's full cluster access for every authenticated user. Hope nobody has a stolen token!

### 6. "The Forgotten Capabilities" — PG-PSS-007/008

```yaml
securityContext:
  capabilities:
    add:
    - NET_ADMIN
    - SYS_PTRACE
```

```
🟠 HIGH | PG-PSS-007 | Container adds dangerous capability NET_ADMIN
🟠 HIGH | PG-PSS-007 | Container adds dangerous capability SYS_PTRACE
```

NET_ADMIN lets you sniff traffic. SYS_PTRACE lets you trace any process. And without `drop: [ALL]`, the container inherits a bunch of default capabilities too.

**Restricted fix:**
```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]  # only if needed
```

---

## Pod Security Standards: The Three Levels

policy-guard checks your manifests against Kubernetes Pod Security Standards:

| Level | What You Get | Who It's For |
|---|---|---|
| **Privileged** | No restrictions | System/infra pods that genuinely need host access |
| **Baseline** | Blocks known escalations (privileged, hostPID, dangerous caps) | Most workloads |
| **Restricted** | Full hardening (drop ALL, runAsNonRoot, seccomp, readOnly root) | Security-sensitive workloads |

```bash
# Check against baseline only
policy-guard scan ./k8s/ --level baseline

# Check against restricted (default)
policy-guard scan ./k8s/ --level restricted
```

The report tells you which level your manifests actually comply with. If it says **PRIVILEGED**, that means nothing is enforced and you're basically running in the wild west.

---

## RBAC: The Silent Escalation Path

RBAC rules are where most clusters quietly hemorrhage security. policy-guard checks for:

| Rule | What It Catches |
|---|---|
| PG-RBAC-001 | Wildcard resources (`resources: ["*"]`) |
| PG-RBAC-002 | Wildcard verbs (`verbs: ["*"]`) |
| PG-RBAC-003 | Write access to Secrets |
| PG-RBAC-004 | Pod exec/attach access |
| PG-RBAC-005 | Escalation verbs (bind, escalate, impersonate) |
| PG-RBAC-006 | Node proxy access (full kubelet API) |
| PG-RBAC-007 | Cluster-admin equivalent (*.*.* permissions) |
| PG-RBAC-008 | Webhook modification (can bypass admission control) |
| PG-RBAC-009 | Binding to default service account |
| PG-RBAC-010 | Binding to cluster-admin |
| PG-RBAC-011 | Binding to system:authenticated/unauthenticated |

The RBAC rules alone would have caught every Kubernetes privilege escalation CVE from the last 3 years.

---

## CI/CD Integration: Stop the YAML Before It Reaches the Cluster

### GitHub Actions

```yaml
- name: Audit K8s Manifests
  run: |
    pip install policy-guard
    policy-guard scan ./k8s/ --fail-on high --format sarif -o results.sarif
- name: Upload SARIF to Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The `--format sarif` flag generates SARIF output that integrates directly with GitHub's Security tab. Your security violations show up alongside CodeQL findings.

### Export Options

```bash
# JSON for scripting
policy-guard scan ./k8s/ --format json -o report.json

# Interactive HTML dashboard
policy-guard scan ./k8s/ --format html -o report.html

# SARIF for GitHub Security
policy-guard scan ./k8s/ --format sarif -o report.sarif
```

---

## The Well-Hardened Deployment

Here's what a Restricted-compliant deployment looks like. policy-guard's demo includes one:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    spec:
      automountServiceAccountToken: false
      serviceAccountName: frontend-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: frontend
        image: gcr.io/myproject/frontend:v2.1.3
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
        resources:
          requests: {memory: 128Mi, cpu: 100m}
          limits: {memory: 256Mi, cpu: 500m}
        livenessProbe:
          httpGet: {path: /healthz, port: 3000}
        readinessProbe:
          httpGet: {path: /ready, port: 3000}
```

This passes almost every rule. **That's what production-ready actually looks like.**

---

## All 50+ Rules at a Glance

```bash
policy-guard rules
```

Organized into 8 categories:

| Category | Rules | Highlights |
|---|---|---|
| 🛡️ **Pod Security** | 19 | privileged, hostPID, capabilities, runAsRoot, seccomp, volumes |
| 🐳 **Image Security** | 4 | :latest tags, missing digest, pull policy |
| 📦 **Container** | 3 | probes, secrets in env vars |
| 📊 **Resource Mgmt** | 4 | missing limits/requests, excessive allocation |
| 🔑 **RBAC** | 11 | wildcards, cluster-admin, secrets, escalation |
| ⚙️ **Workload** | 7 | single replica, no PDB, no strategy |
| 🌐 **Network** | 5 | LoadBalancer, NodePort, Ingress TLS, snippets |
| 💪 **Reliability** | varies | anti-affinity, topology spread, priority |

Each rule maps to CIS Kubernetes Benchmark IDs where applicable.

---

## Get Started

```bash
# Install
pip install policy-guard

# Run the demo (no cluster needed)
policy-guard demo

# Scan your manifests
policy-guard scan ./k8s/ --verbose

# CI/CD gate
policy-guard scan ./k8s/ --fail-on high
```

**GitHub:** [github.com/SanjaySundarMurthy/policy-guard](https://github.com/SanjaySundarMurthy/policy-guard)

Star it. Run it on your production manifests. I'll wait.

---

*Your Kubernetes manifests are only as secure as the worst YAML in the repo. policy-guard makes sure that worst YAML never makes it past code review.*
