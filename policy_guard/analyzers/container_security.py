"""Container and image security analyzer.

Rules PG-IMG-001 through PG-IMG-004 and PG-CTR-001 through PG-CTR-007.
"""
import re

from policy_guard.models import Violation, Severity, Category
from policy_guard.parser import get_containers, get_pod_spec

# Trusted registries (common defaults)
KNOWN_REGISTRIES = {
    "docker.io", "gcr.io", "ghcr.io", "quay.io",
    "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws",
}

# Images that typically run as root
ROOT_IMAGES = {
    "nginx", "httpd", "mysql", "postgres", "mariadb",
    "redis", "mongo", "elasticsearch", "jenkins",
}

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def analyze(resources: list) -> list:
    violations = []
    for res in resources:
        if res.kind not in WORKLOAD_KINDS:
            continue
        containers = get_containers(res)
        pod_spec = get_pod_spec(res)
        if not containers:
            continue

        for c in containers:
            _check_image_tag(res, c, violations)
            _check_image_digest(res, c, violations)
            _check_image_pull_policy(res, c, violations)
            _check_liveness_probe(res, c, violations)
            _check_readiness_probe(res, c, violations)
            _check_resource_limits(res, c, violations)
            _check_resource_requests(res, c, violations)
            _check_cpu_limits(res, c, violations)
            _check_memory_limits(res, c, violations)
            _check_env_secrets(res, c, violations)

        _check_image_pull_secrets(res, pod_spec, violations)

    return violations


def _check_image_tag(res, c, violations):
    """PG-IMG-001: Image uses 'latest' tag or no tag."""
    image = c.get("image", "")
    if not image:
        violations.append(Violation(
            rule_id="PG-IMG-001",
            severity=Severity.HIGH,
            category=Category.IMAGE,
            message=f"Container '{c.get('name', '?')}' has no image specified",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            suggestion="Specify a container image with a specific version tag",
        ))
        return

    # Check for latest or missing tag
    if ":" not in image or image.endswith(":latest"):
        violations.append(Violation(
            rule_id="PG-IMG-001",
            severity=Severity.HIGH,
            category=Category.IMAGE,
            message=f"Container '{c.get('name', '?')}' uses image '{image}' with 'latest' or no tag",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            field_path="spec.containers[].image",
            suggestion="Pin images to a specific version tag (e.g., nginx:1.25.3)",
            cis_id="5.5.1",
        ))


def _check_image_digest(res, c, violations):
    """PG-IMG-002: Image not pinned to digest."""
    image = c.get("image", "")
    if image and "@sha256:" not in image:
        violations.append(Violation(
            rule_id="PG-IMG-002",
            severity=Severity.LOW,
            category=Category.IMAGE,
            message=f"Container '{c.get('name', '?')}' image not pinned to digest",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            suggestion="Pin images to a SHA256 digest for immutability (e.g., nginx@sha256:abc...)",
        ))


def _check_image_pull_policy(res, c, violations):
    """PG-IMG-003: imagePullPolicy not set to Always."""
    image = c.get("image", "")
    policy = c.get("imagePullPolicy", "")

    if ":latest" in image or ":" not in image:
        if policy != "Always":
            violations.append(Violation(
                rule_id="PG-IMG-003",
                severity=Severity.MEDIUM,
                category=Category.IMAGE,
                message=f"Container '{c.get('name', '?')}' uses 'latest' without imagePullPolicy: Always",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                suggestion="Set imagePullPolicy to 'Always' when using mutable tags",
            ))


def _check_liveness_probe(res, c, violations):
    """PG-CTR-001: Missing liveness probe."""
    if not c.get("livenessProbe"):
        violations.append(Violation(
            rule_id="PG-CTR-001",
            severity=Severity.MEDIUM,
            category=Category.RELIABILITY,
            message=f"Container '{c.get('name', '?')}' missing liveness probe",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            field_path="spec.containers[].livenessProbe",
            suggestion="Add a livenessProbe to detect unhealthy containers",
        ))


def _check_readiness_probe(res, c, violations):
    """PG-CTR-002: Missing readiness probe."""
    if not c.get("readinessProbe"):
        violations.append(Violation(
            rule_id="PG-CTR-002",
            severity=Severity.MEDIUM,
            category=Category.RELIABILITY,
            message=f"Container '{c.get('name', '?')}' missing readiness probe",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            field_path="spec.containers[].readinessProbe",
            suggestion="Add a readinessProbe to control traffic routing",
        ))


def _check_resource_limits(res, c, violations):
    """PG-CTR-003: Missing resource limits."""
    resources = c.get("resources", {}) or {}
    if not resources.get("limits"):
        violations.append(Violation(
            rule_id="PG-CTR-003",
            severity=Severity.HIGH,
            category=Category.RESOURCE,
            message=f"Container '{c.get('name', '?')}' has no resource limits",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            field_path="spec.containers[].resources.limits",
            suggestion="Set memory and CPU limits to prevent resource exhaustion",
            fix_yaml="resources:\n  limits:\n    memory: 256Mi\n    cpu: 500m",
            cis_id="5.4.1",
        ))


def _check_resource_requests(res, c, violations):
    """PG-CTR-004: Missing resource requests."""
    resources = c.get("resources", {}) or {}
    if not resources.get("requests"):
        violations.append(Violation(
            rule_id="PG-CTR-004",
            severity=Severity.MEDIUM,
            category=Category.RESOURCE,
            message=f"Container '{c.get('name', '?')}' has no resource requests",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            container_name=c.get("name", ""),
            field_path="spec.containers[].resources.requests",
            suggestion="Set resource requests for proper scheduling",
        ))


def _check_cpu_limits(res, c, violations):
    """PG-CTR-005: CPU limit is too high."""
    resources = c.get("resources", {}) or {}
    limits = resources.get("limits", {}) or {}
    cpu = limits.get("cpu", "")

    if cpu:
        cpu_val = _parse_cpu(str(cpu))
        if cpu_val and cpu_val > 4.0:
            violations.append(Violation(
                rule_id="PG-CTR-005",
                severity=Severity.LOW,
                category=Category.RESOURCE,
                message=f"Container '{c.get('name', '?')}' has high CPU limit: {cpu} ({cpu_val} cores)",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                suggestion="Consider reducing CPU limit unless this workload needs >4 cores",
            ))


def _check_memory_limits(res, c, violations):
    """PG-CTR-006: Memory limit is too high."""
    resources = c.get("resources", {}) or {}
    limits = resources.get("limits", {}) or {}
    mem = limits.get("memory", "")

    if mem:
        mem_bytes = _parse_memory(str(mem))
        if mem_bytes and mem_bytes > 8 * 1024**3:  # 8Gi
            violations.append(Violation(
                rule_id="PG-CTR-006",
                severity=Severity.LOW,
                category=Category.RESOURCE,
                message=f"Container '{c.get('name', '?')}' has high memory limit: {mem}",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                suggestion="Consider reducing memory limit unless this workload needs >8Gi",
            ))


def _check_env_secrets(res, c, violations):
    """PG-CTR-007: Secrets in environment variables."""
    SECRET_PATTERNS = re.compile(
        r"(password|secret|token|api_key|apikey|access_key|private_key|credentials)",
        re.IGNORECASE,
    )

    for env in (c.get("env") or []):
        name = env.get("name", "")
        value = env.get("value")
        if value and SECRET_PATTERNS.search(name):
            violations.append(Violation(
                rule_id="PG-CTR-007",
                severity=Severity.HIGH,
                category=Category.CONTAINER,
                message=f"Container '{c.get('name', '?')}' has potential secret in env var '{name}'",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path=f"spec.containers[].env[name={name}]",
                suggestion="Use Kubernetes Secrets or external secret managers instead of inline values",
            ))


def _check_image_pull_secrets(res, pod_spec, violations):
    """PG-IMG-004: No imagePullSecrets for private registries."""
    containers = list(pod_spec.get("containers", []) or [])
    has_private = False
    for c in containers:
        image = c.get("image", "")
        registry = image.split("/")[0] if "/" in image else ""
        if registry and "." in registry and registry not in KNOWN_REGISTRIES:
            has_private = True
            break

    if has_private and not pod_spec.get("imagePullSecrets"):
        violations.append(Violation(
            rule_id="PG-IMG-004",
            severity=Severity.MEDIUM,
            category=Category.IMAGE,
            message="Uses private registry but no imagePullSecrets configured",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Add imagePullSecrets to pull from private registries",
        ))


def _parse_cpu(cpu_str: str) -> float:
    """Parse CPU string to cores (float)."""
    try:
        if cpu_str.endswith("m"):
            return float(cpu_str[:-1]) / 1000
        return float(cpu_str)
    except (ValueError, IndexError):
        return 0.0


def _parse_memory(mem_str: str) -> int:
    """Parse memory string to bytes."""
    suffixes = {
        "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
        "K": 1000, "M": 1000**2, "G": 1000**3, "T": 1000**4,
    }
    for suffix, multiplier in suffixes.items():
        if mem_str.endswith(suffix):
            try:
                return int(float(mem_str[:-len(suffix)]) * multiplier)
            except ValueError:
                return 0
    try:
        return int(mem_str)
    except ValueError:
        return 0
