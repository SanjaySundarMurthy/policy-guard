"""Workload and network exposure analyzer.

Rules PG-WRK-001 through PG-WRK-007 and PG-NET-001 through PG-NET-005.
"""
from policy_guard.models import Violation, Severity, Category
from policy_guard.parser import get_pod_spec

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def analyze(resources: list) -> list:
    violations = []
    workloads = [r for r in resources if r.kind in WORKLOAD_KINDS]
    services = [r for r in resources if r.kind == "Service"]
    ingresses = [r for r in resources if r.kind == "Ingress"]

    for res in workloads:
        pod_spec = get_pod_spec(res)
        if not pod_spec:
            continue
        _check_replicas(res, violations)
        _check_strategy(res, violations)
        _check_pod_disruption_budget(res, resources, violations)
        _check_topology_spread(res, pod_spec, violations)
        _check_priority_class(res, pod_spec, violations)
        _check_termination_grace(res, pod_spec, violations)
        _check_pod_anti_affinity(res, pod_spec, violations)

    for svc in services:
        _check_load_balancer(svc, violations)
        _check_node_port(svc, violations)
        _check_external_name(svc, violations)

    for ing in ingresses:
        _check_ingress_tls(ing, violations)
        _check_ingress_annotations(ing, violations)

    return violations


def _check_replicas(res, violations):
    """PG-WRK-001: Single replica deployment."""
    if res.kind not in ("Deployment", "StatefulSet"):
        return
    replicas = res.spec.get("replicas")
    if replicas is not None and replicas < 2:
        violations.append(Violation(
            rule_id="PG-WRK-001",
            severity=Severity.LOW,
            category=Category.RELIABILITY,
            message=f"{res.kind}/{res.name} has only {replicas} replica(s)",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Use at least 2 replicas for high availability",
        ))


def _check_strategy(res, violations):
    """PG-WRK-002: Missing update strategy."""
    if res.kind != "Deployment":
        return
    strategy = res.spec.get("strategy", {})
    if not strategy:
        violations.append(Violation(
            rule_id="PG-WRK-002",
            severity=Severity.LOW,
            category=Category.WORKLOAD,
            message=f"Deployment/{res.name} has no explicit update strategy",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Set strategy.type to 'RollingUpdate' with maxSurge/maxUnavailable",
        ))


def _check_pod_disruption_budget(res, all_resources, violations):
    """PG-WRK-003: No PodDisruptionBudget."""
    if res.kind not in ("Deployment", "StatefulSet"):
        return
    replicas = res.spec.get("replicas", 1)
    if replicas < 2:
        return

    pdbs = [r for r in all_resources if r.kind == "PodDisruptionBudget"]
    template = res.spec.get("template", {}) or {}
    pod_labels = (template.get("metadata", {}) or {}).get("labels", {}) or {}

    has_pdb = False
    for pdb in pdbs:
        selector = pdb.spec.get("selector", {}) or {}
        match_labels = selector.get("matchLabels", {}) or {}
        if match_labels and all(pod_labels.get(k) == v for k, v in match_labels.items()):
            has_pdb = True
            break

    if not has_pdb:
        violations.append(Violation(
            rule_id="PG-WRK-003",
            severity=Severity.MEDIUM,
            category=Category.RELIABILITY,
            message=f"{res.kind}/{res.name} has {replicas} replicas but no PodDisruptionBudget",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Create a PodDisruptionBudget to protect availability during upgrades/evictions",
        ))


def _check_topology_spread(res, pod_spec, violations):
    """PG-WRK-004: No topology spread constraints."""
    if res.kind not in ("Deployment", "StatefulSet"):
        return
    replicas = res.spec.get("replicas", 1)
    if replicas < 2:
        return

    if not pod_spec.get("topologySpreadConstraints"):
        violations.append(Violation(
            rule_id="PG-WRK-004",
            severity=Severity.INFO,
            category=Category.RELIABILITY,
            message=f"{res.kind}/{res.name} has no topology spread constraints",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Add topologySpreadConstraints to distribute pods across failure domains",
        ))


def _check_priority_class(res, pod_spec, violations):
    """PG-WRK-005: No priorityClassName set."""
    if res.kind in ("Job", "CronJob"):
        return
    if not pod_spec.get("priorityClassName"):
        violations.append(Violation(
            rule_id="PG-WRK-005",
            severity=Severity.INFO,
            category=Category.WORKLOAD,
            message=f"{res.kind}/{res.name} has no priorityClassName",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Set priorityClassName to control scheduling priority during resource pressure",
        ))


def _check_termination_grace(res, pod_spec, violations):
    """PG-WRK-006: Very short termination grace period."""
    grace = pod_spec.get("terminationGracePeriodSeconds")
    if grace is not None and grace < 10:
        violations.append(Violation(
            rule_id="PG-WRK-006",
            severity=Severity.LOW,
            category=Category.WORKLOAD,
            message=f"{res.kind}/{res.name} has terminationGracePeriod of {grace}s (too short)",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Set at least 30s to allow graceful shutdown",
        ))


def _check_pod_anti_affinity(res, pod_spec, violations):
    """PG-WRK-007: Multi-replica without anti-affinity."""
    if res.kind not in ("Deployment", "StatefulSet"):
        return
    replicas = res.spec.get("replicas", 1)
    if replicas < 2:
        return

    affinity = pod_spec.get("affinity", {}) or {}
    anti = affinity.get("podAntiAffinity")
    if not anti:
        violations.append(Violation(
            rule_id="PG-WRK-007",
            severity=Severity.INFO,
            category=Category.RELIABILITY,
            message=f"{res.kind}/{res.name} has {replicas} replicas but no podAntiAffinity",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            suggestion="Add podAntiAffinity to spread replicas across nodes",
        ))


def _check_load_balancer(svc, violations):
    """PG-NET-001: LoadBalancer service without restrictions."""
    spec = svc.spec
    if spec.get("type") == "LoadBalancer":
        if not spec.get("loadBalancerSourceRanges"):
            violations.append(Violation(
                rule_id="PG-NET-001",
                severity=Severity.HIGH,
                category=Category.NETWORK,
                message=f"Service/{svc.name} is LoadBalancer without loadBalancerSourceRanges",
                resource_kind=svc.kind,
                resource_name=svc.name,
                namespace=svc.namespace,
                file_path=svc.file_path,
                suggestion="Restrict access with loadBalancerSourceRanges or use an Ingress controller",
            ))


def _check_node_port(svc, violations):
    """PG-NET-002: NodePort service."""
    if svc.spec.get("type") == "NodePort":
        violations.append(Violation(
            rule_id="PG-NET-002",
            severity=Severity.MEDIUM,
            category=Category.NETWORK,
            message=f"Service/{svc.name} uses NodePort — exposes port on all cluster nodes",
            resource_kind=svc.kind,
            resource_name=svc.name,
            namespace=svc.namespace,
            file_path=svc.file_path,
            suggestion="Use ClusterIP with an Ingress controller instead of NodePort",
        ))


def _check_external_name(svc, violations):
    """PG-NET-003: ExternalName service (potential SSRF vector)."""
    if svc.spec.get("type") == "ExternalName":
        external = svc.spec.get("externalName", "")
        violations.append(Violation(
            rule_id="PG-NET-003",
            severity=Severity.MEDIUM,
            category=Category.NETWORK,
            message=f"Service/{svc.name} is ExternalName pointing to '{external}'",
            resource_kind=svc.kind,
            resource_name=svc.name,
            namespace=svc.namespace,
            file_path=svc.file_path,
            suggestion="Verify ExternalName target is trusted — ExternalName can be used for SSRF",
        ))


def _check_ingress_tls(ing, violations):
    """PG-NET-004: Ingress without TLS."""
    tls = ing.spec.get("tls")
    if not tls:
        violations.append(Violation(
            rule_id="PG-NET-004",
            severity=Severity.HIGH,
            category=Category.NETWORK,
            message=f"Ingress/{ing.name} has no TLS configuration",
            resource_kind=ing.kind,
            resource_name=ing.name,
            namespace=ing.namespace,
            file_path=ing.file_path,
            suggestion="Add TLS termination to encrypt traffic in transit",
        ))


def _check_ingress_annotations(ing, violations):
    """PG-NET-005: Dangerous Ingress annotations."""
    dangerous_annotations = {
        "nginx.ingress.kubernetes.io/server-snippet": "Server snippets allow arbitrary nginx config injection",
        "nginx.ingress.kubernetes.io/configuration-snippet": "Config snippets can leak secrets via log injection",
    }

    for annotation, reason in dangerous_annotations.items():
        if annotation in ing.annotations:
            violations.append(Violation(
                rule_id="PG-NET-005",
                severity=Severity.HIGH,
                category=Category.NETWORK,
                message=f"Ingress/{ing.name} uses dangerous annotation '{annotation}'",
                resource_kind=ing.kind,
                resource_name=ing.name,
                namespace=ing.namespace,
                file_path=ing.file_path,
                suggestion=f"Remove annotation — {reason}",
            ))
