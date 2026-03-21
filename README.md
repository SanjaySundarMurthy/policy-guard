# policy-guard

<div align="center">

[![CI](https://github.com/SanjaySundarMurthy/policy-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/policy-guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/k8s-policy-guard)](https://pypi.org/project/k8s-policy-guard/)
[![PyPI](https://img.shields.io/pypi/v/k8s-policy-guard)](https://pypi.org/project/k8s-policy-guard/)
[![Downloads](https://img.shields.io/pypi/dm/k8s-policy-guard)](https://pypi.org/project/k8s-policy-guard/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Kubernetes Manifest Security Auditor**

*Shift security left - catch misconfigurations before they hit the cluster*

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Rules](https://img.shields.io/badge/validation%20rules-50+-orange.svg)
![PSS](https://img.shields.io/badge/Pod%20Security%20Standards-Baseline%20%2B%20Restricted-green.svg)
![CIS](https://img.shields.io/badge/CIS%20Benchmarks-Mapped-blue.svg)

</div>

---

## Table of Contents

- [Why policy-guard?](#why-policy-guard)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Validation Rules](#-validation-rules)
- [Severity Levels](#-severity-levels)
- [Pod Security Standards](#-pod-security-standards-compliance)
- [CI/CD Integration](#-cicd-integration)
- [Output Formats](#-output-formats)
- [Architecture](#-architecture)
- [Docker](#-docker)
- [Contributing](#-contributing)
- [License](#-license)

---

## Why policy-guard?

Kubernetes security is a minefield. One `privileged: true`, one `runAsUser: 0`, one wildcard RBAC rule - and your cluster becomes an open buffet for attackers.

Pod Security Admission helps, but only at deploy time. By then it's already too late.

**policy-guard shifts security left:**

```
Developer writes K8s manifest
        |
        v
policy-guard scans for security issues  <-- Catches problems HERE
        |
        v
Fixed before code review
        |
        v
CI/CD pipeline (additional validation)
        |
        v
Secure deployment to cluster
```

---

## Features

| Feature | Description |
|---------|-------------|
| **50+ Security Rules** | Comprehensive checks across 8 categories |
| **Pod Security Standards** | Full PSS compliance (Privileged, Baseline, Restricted) |
| **CIS Benchmark Mapping** | Rules mapped to CIS Kubernetes Benchmark IDs |
| **RBAC Analysis** | Detect over-privileged roles, wildcard permissions, cluster-admin bindings |
| **Container Security** | Image tags, probes, resource limits, secrets in env vars |
| **Network Exposure** | LoadBalancer, NodePort, Ingress TLS checks |
| **Security Scoring** | A+ to F grading with detailed breakdown |
| **Multiple Output Formats** | Terminal, JSON, HTML dashboard, SARIF |
| **CI/CD Ready** | `--fail-on` threshold for pipeline integration |
| **Fix Suggestions** | Actionable remediation for every issue |

---

## Installation

```bash
pip install k8s-policy-guard
```

**Requirements:** Python 3.8+

---

## Quick Start

### Demo Mode (No Cluster Needed)

```bash
policy-guard demo
```

Creates realistic K8s manifests with intentional security issues and runs a full audit.

### Scan Your Manifests

```bash
# Scan a single file
policy-guard scan deployment.yaml

# Scan a directory (recursive)
policy-guard scan ./k8s/

# Verbose mode - show fix suggestions and CIS mappings
policy-guard scan ./k8s/ --verbose

# Target a specific Pod Security Standard level
policy-guard scan ./k8s/ --level baseline
```

### Export Reports

```bash
# JSON report for programmatic processing
policy-guard scan ./k8s/ --format json -o report.json

# Interactive HTML dashboard
policy-guard scan ./k8s/ --format html -o report.html

# SARIF for GitHub Security tab integration
policy-guard scan ./k8s/ --format sarif -o report.sarif
```

### List All Rules

```bash
policy-guard rules
```

---

## Validation Rules

**50+ rules** organized into **8 categories**:

| Category | Rule IDs | What It Catches |
|----------|----------|-----------------|
| **Pod Security** | PG-PSS-001 to 019 | privileged containers, hostPID/IPC/Network, dangerous capabilities, runAsRoot, seccomp, volume types |
| **Image Security** | PG-IMG-001 to 004 | latest tags, missing digests, pull policy, private registries without secrets |
| **Container** | PG-CTR-001 to 007 | missing probes, no resource limits/requests, secrets in env vars |
| **RBAC** | PG-RBAC-001 to 011 | wildcard permissions, cluster-admin bindings, secrets write access, pod exec, privilege escalation |
| **Workload** | PG-WRK-001 to 007 | single replica, no PDB, no update strategy, no anti-affinity |
| **Network** | PG-NET-001 to 005 | LoadBalancer without sourceRanges, NodePort, Ingress without TLS, dangerous annotations |
| **Resource Mgmt** | PG-CTR-003 to 006 | missing limits/requests, excessive CPU/memory allocations |
| **Reliability** | PG-WRK-001 to 007 | single replica, no PDB, no topology spread constraints |

---

## Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Immediate security risk | Privileged container, cluster-admin binding |
| **HIGH** | Significant vulnerability | No resource limits, secrets in env vars |
| **MEDIUM** | Recommended fix | Missing probes, NodePort service |
| **LOW** | Best practice | Single replica, no update strategy |
| **INFO** | Suggestion | No topology spread, no priorityClassName |

---

## Pod Security Standards Compliance

policy-guard validates against all three Kubernetes PSS levels:

| Level | Enforcement | Key Controls |
|-------|-------------|--------------|
| **Privileged** | None | Anything goes - no restrictions |
| **Baseline** | Moderate | Blocks known privilege escalations (privileged, hostPID, dangerous capabilities) |
| **Restricted** | Strict | Full hardening (drop ALL caps, runAsNonRoot, seccomp, readOnlyRootFilesystem) |

The report shows which PSS level your manifests comply with.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install policy-guard
        run: pip install k8s-policy-guard
      
      - name: Audit K8s Manifests
        run: policy-guard scan ./k8s/ --fail-on high --format sarif -o results.sarif
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-audit:
  image: python:3.12
  script:
    - pip install k8s-policy-guard
    - policy-guard scan ./k8s/ --fail-on high --format json -o report.json
  artifacts:
    reports:
      security: report.json
```

### Azure DevOps

```yaml
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.12'
    
- script: |
    pip install k8s-policy-guard
    policy-guard scan ./k8s/ --fail-on high
  displayName: 'Security Audit'
```

---

## Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| **Terminal** | Interactive development | `policy-guard scan ./k8s/` |
| **JSON** | Programmatic processing, custom dashboards | `--format json -o report.json` |
| **HTML** | Shareable reports, management review | `--format html -o report.html` |
| **SARIF** | GitHub Security tab, IDE integration | `--format sarif -o report.sarif` |

---

## Architecture

```
policy_guard/
 ├── __init__.py          # Package metadata
 ├── cli.py               # Click CLI (scan, demo, rules commands)
 ├── models.py            # Violation, Resource, AuditReport dataclasses
 ├── parser.py            # YAML parser supporting all K8s resource types
 ├── demo.py              # Demo scenario generator
 ├── analyzers/
 │   ├── pod_security.py      # PSS rules (PG-PSS-001 to 019)
 │   ├── container_security.py # Image + container rules (PG-IMG/CTR)
 │   ├── rbac_analyzer.py     # RBAC rules (PG-RBAC-001 to 011)
 │   └── workload_analyzer.py # Workload + network rules (PG-WRK/NET)
 └── reporters/
     ├── terminal_reporter.py  # Rich terminal output with colors
     └── export_reporter.py    # JSON, HTML, SARIF export
```

---

## Docker

Run without installing Python:

```bash
# Build the image
docker build -t policy-guard .

# Run with mounted manifests
docker run --rm -v ${PWD}:/workspace policy-guard scan /workspace/k8s/

# Quick help
docker run --rm policy-guard --help

# Demo mode
docker run --rm policy-guard demo
```

Pull from container registry:

```bash
docker pull ghcr.io/SanjaySundarMurthy/policy-guard:latest
docker run --rm ghcr.io/SanjaySundarMurthy/policy-guard:latest --help
```

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run linter
ruff check .

# Run with coverage
pytest --cov=policy_guard
```

**Test Coverage:** 60 tests covering CLI, analyzers, models, and parser.

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Write tests** for your changes
4. **Ensure** all tests pass: `pytest -v`
5. **Ensure** linting passes: `ruff check .`
6. **Commit** your changes: `git commit -m 'Add amazing feature'`
7. **Push** to the branch: `git push origin feature/amazing-feature`
8. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/SanjaySundarMurthy/policy-guard.git
cd policy-guard
pip install -e ".[dev]"
pytest -v
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**Sanjay Sundar Murthy** - Built with love for Kubernetes security.

---

<div align="center">

**[Report Bug](https://github.com/SanjaySundarMurthy/policy-guard/issues)** | **[Request Feature](https://github.com/SanjaySundarMurthy/policy-guard/issues)** | **[Documentation](https://github.com/SanjaySundarMurthy/policy-guard#readme)**

</div>
