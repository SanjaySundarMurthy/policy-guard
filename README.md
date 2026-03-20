# policy-guard

**Kubernetes Manifest Security Auditor**

A comprehensive CLI tool that audits Kubernetes YAML manifests against Pod Security Standards, CIS Kubernetes Benchmarks, RBAC best practices, and container security rules — all without requiring a running cluster.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Rules](https://img.shields.io/badge/validation%20rules-50+-orange.svg)
![PSS](https://img.shields.io/badge/Pod%20Security%20Standards-Baseline%20%2B%20Restricted-green.svg)

---

## Why policy-guard?

Kubernetes security is a minefield. One `privileged: true`, one `runAsUser: 0`, one wildcard RBAC rule, and your cluster is an open buffet. Pod Security Admission helps, but only at deploy time — by then it's too late.

**policy-guard** shifts security left:

- **50+ validation rules** across 8 categories
- **Pod Security Standards** compliance (Privileged, Baseline, Restricted)
- **CIS Kubernetes Benchmark** mappings
- **RBAC analysis** detecting wildcard permissions, cluster-admin bindings, and privilege escalation
- **Container security** checks (image tags, probes, resources, secrets in env vars)
- **Network exposure** analysis (LoadBalancer, NodePort, Ingress TLS)
- **SARIF output** for GitHub Security tab integration
- **CI/CD ready** with `--fail-on` severity threshold

---

## Installation

```bash
pip install -e .
```

---

## Quick Start

### Demo Mode (No Cluster Needed)

```bash
policy-guard demo
```

Creates a realistic production cluster with intentional security issues and runs a full audit.

### Scan Manifests

```bash
# Scan a single file
policy-guard scan deployment.yaml

# Scan a directory
policy-guard scan ./k8s/

# Verbose mode with fix suggestions and CIS mappings
policy-guard scan ./k8s/ --verbose

# Target a specific PSS level
policy-guard scan ./k8s/ --level baseline
```

### Export Reports

```bash
# JSON report
policy-guard scan ./k8s/ --format json -o report.json

# Interactive HTML dashboard
policy-guard scan ./k8s/ --format html -o report.html

# SARIF for GitHub Security tab
policy-guard scan ./k8s/ --format sarif -o report.sarif
```

### CI/CD Integration

```bash
# Fail on critical or high severity
policy-guard scan ./k8s/ --fail-on high
```

```yaml
# .github/workflows/security-audit.yml
- name: Audit K8s Manifests
  run: |
    pip install policy-guard
    policy-guard scan ./k8s/ --fail-on high --format sarif -o results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Validation Rules

50+ rules organized into 8 categories:

| Category | Rules | What It Catches |
|---|---|---|
| **Pod Security** | PG-PSS-001 to PSS-019 | privileged, hostPID/IPC/Network, capabilities, runAsRoot, seccomp, volumes |
| **Image Security** | PG-IMG-001 to IMG-004 | latest tags, missing digests, pull policy, private registries |
| **Container** | PG-CTR-001 to CTR-007 | missing probes, no limits/requests, secrets in env vars |
| **RBAC** | PG-RBAC-001 to RBAC-011 | wildcards, cluster-admin, secrets write, pod exec, escalation verbs |
| **Workload** | PG-WRK-001 to WRK-007 | single replica, no PDB, no strategy, no anti-affinity |
| **Network** | PG-NET-001 to NET-005 | LoadBalancer without sourceRanges, NodePort, Ingress without TLS |
| **Resource Mgmt** | PG-CTR-003 to CTR-006 | missing limits/requests, excessive allocations |
| **Reliability** | PG-WRK-001 to WRK-007 | single replica, no PDB, no topology spread |

```bash
policy-guard rules  # View all rules with severity levels
```

---

## Pod Security Standards Compliance

policy-guard checks compliance against all three Kubernetes PSS levels:

| Level | What It Enforces |
|---|---|
| **Privileged** | No restrictions (anything goes) |
| **Baseline** | Blocks known privilege escalations (privileged, hostPID, dangerous capabilities) |
| **Restricted** | Full hardening (drop ALL caps, runAsNonRoot, seccomp, readOnlyRootFilesystem) |

The report shows which PSS level your manifests comply with.

---

## Architecture

```
policy_guard/
├── cli.py               # Click CLI entry point (scan, demo, rules)
├── models.py            # Violation, Resource, AuditReport models
├── parser.py            # YAML parser (all K8s resource types)
├── demo.py              # Demo scenario generator
├── analyzers/
│   ├── pod_security.py      # PSS rules (PG-PSS-001 → PSS-019)
│   ├── container_security.py # Image + container rules (PG-IMG/CTR)
│   ├── rbac_analyzer.py     # RBAC rules (PG-RBAC-001 → RBAC-011)
│   └── workload_analyzer.py # Workload + network rules (PG-WRK/NET)
└── reporters/
    ├── terminal_reporter.py  # Rich terminal output
    └── export_reporter.py    # JSON + HTML + SARIF export
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**sanjaysundarmurthy** — Built with ❤️ for Kubernetes security.
