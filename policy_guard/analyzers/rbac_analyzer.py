"""RBAC analyzer — checks Roles, ClusterRoles, and bindings for over-privilege.

Rules PG-RBAC-001 through PG-RBAC-012.
"""
from policy_guard.models import Violation, Severity, Category, Resource

# Dangerous verb combinations
DANGEROUS_VERBS = {"*", "create", "update", "patch", "delete", "escalate", "bind", "impersonate"}
WILDCARD_VERBS = {"*"}
SENSITIVE_RESOURCES = {
    "secrets", "configmaps", "pods/exec", "pods/attach", "pods/portforward",
    "nodes", "nodes/proxy", "clusterroles", "clusterrolebindings",
    "roles", "rolebindings", "serviceaccounts", "serviceaccounts/token",
    "certificatesigningrequests", "validatingwebhookconfigurations",
    "mutatingwebhookconfigurations", "customresourcedefinitions",
    "namespaces", "persistentvolumes",
}


def analyze(resources: list) -> list:
    violations = []

    roles = [r for r in resources if r.kind in ("Role", "ClusterRole")]
    bindings = [r for r in resources if r.kind in ("RoleBinding", "ClusterRoleBinding")]

    for role in roles:
        _check_wildcard_resources(role, violations)
        _check_wildcard_verbs(role, violations)
        _check_secrets_access(role, violations)
        _check_exec_access(role, violations)
        _check_escalation_verbs(role, violations)
        _check_node_proxy(role, violations)
        _check_cluster_admin_like(role, violations)
        _check_webhook_access(role, violations)

    for binding in bindings:
        _check_default_sa_binding(binding, violations)
        _check_cluster_admin_binding(binding, violations)
        _check_all_groups_binding(binding, violations)

    return violations


def _get_rules(role: Resource) -> list:
    return role.raw.get("rules") or role.spec.get("rules") or []


def _check_wildcard_resources(role, violations):
    """PG-RBAC-001: Wildcard resources."""
    for rule in _get_rules(role):
        resources = rule.get("resources", [])
        if "*" in resources:
            violations.append(Violation(
                rule_id="PG-RBAC-001",
                severity=Severity.HIGH,
                category=Category.RBAC,
                message=f"{'Cluster' if role.kind == 'ClusterRole' else ''}Role '{role.name}' grants access to ALL resources ('*')",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                field_path="rules[].resources",
                suggestion="List specific resources instead of using '*'",
                cis_id="5.1.3",
            ))
            break


def _check_wildcard_verbs(role, violations):
    """PG-RBAC-002: Wildcard verbs."""
    for rule in _get_rules(role):
        verbs = rule.get("verbs", [])
        if "*" in verbs:
            violations.append(Violation(
                rule_id="PG-RBAC-002",
                severity=Severity.HIGH,
                category=Category.RBAC,
                message=f"Role '{role.name}' grants ALL verbs ('*')",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                field_path="rules[].verbs",
                suggestion="List specific verbs (get, list, watch) instead of '*'",
                cis_id="5.1.3",
            ))
            break


def _check_secrets_access(role, violations):
    """PG-RBAC-003: Write access to secrets."""
    write_verbs = {"create", "update", "patch", "delete", "*"}
    for rule in _get_rules(role):
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        if "secrets" in resources and verbs & write_verbs:
            violations.append(Violation(
                rule_id="PG-RBAC-003",
                severity=Severity.CRITICAL,
                category=Category.RBAC,
                message=f"Role '{role.name}' grants write access to Secrets",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                suggestion="Grant read-only access to secrets or use external secret managers",
                cis_id="5.1.2",
            ))
            break


def _check_exec_access(role, violations):
    """PG-RBAC-004: Pod exec/attach access."""
    for rule in _get_rules(role):
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        if resources & {"pods/exec", "pods/attach"} and verbs & {"create", "get", "*"}:
            violations.append(Violation(
                rule_id="PG-RBAC-004",
                severity=Severity.HIGH,
                category=Category.RBAC,
                message=f"Role '{role.name}' grants pod exec/attach access",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                suggestion="Restrict exec/attach access to specific service accounts for debugging only",
                cis_id="5.1.4",
            ))
            break


def _check_escalation_verbs(role, violations):
    """PG-RBAC-005: Escalation verbs (bind, escalate, impersonate)."""
    dangerous = {"escalate", "bind", "impersonate"}
    for rule in _get_rules(role):
        verbs = set(rule.get("verbs", []))
        found = verbs & dangerous
        if found:
            violations.append(Violation(
                rule_id="PG-RBAC-005",
                severity=Severity.CRITICAL,
                category=Category.RBAC,
                message=f"Role '{role.name}' grants privilege escalation verbs: {', '.join(sorted(found))}",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                suggestion="Remove escalation verbs unless absolutely necessary",
            ))
            break


def _check_node_proxy(role, violations):
    """PG-RBAC-006: Node proxy access."""
    for rule in _get_rules(role):
        resources = set(rule.get("resources", []))
        if resources & {"nodes/proxy", "nodes"}:
            verbs = set(rule.get("verbs", []))
            if verbs & {"create", "*"}:
                violations.append(Violation(
                    rule_id="PG-RBAC-006",
                    severity=Severity.CRITICAL,
                    category=Category.RBAC,
                    message=f"Role '{role.name}' grants node proxy access (full kubelet API)",
                    resource_kind=role.kind,
                    resource_name=role.name,
                    namespace=role.namespace,
                    file_path=role.file_path,
                    suggestion="Remove node/proxy access — this allows executing commands on any node",
                ))
                break


def _check_cluster_admin_like(role, violations):
    """PG-RBAC-007: ClusterRole with cluster-admin-like permissions."""
    if role.kind != "ClusterRole":
        return

    for rule in _get_rules(role):
        resources = rule.get("resources", [])
        verbs = rule.get("verbs", [])
        api_groups = rule.get("apiGroups", [])

        if "*" in resources and "*" in verbs and "*" in api_groups:
            violations.append(Violation(
                rule_id="PG-RBAC-007",
                severity=Severity.CRITICAL,
                category=Category.RBAC,
                message=f"ClusterRole '{role.name}' is cluster-admin equivalent (*.*.* permissions)",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                suggestion="Use the built-in 'cluster-admin' ClusterRole or scope permissions",
            ))
            break


def _check_webhook_access(role, violations):
    """PG-RBAC-008: Write access to webhooks."""
    webhook_resources = {"validatingwebhookconfigurations", "mutatingwebhookconfigurations"}
    write_verbs = {"create", "update", "patch", "delete", "*"}
    for rule in _get_rules(role):
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        if resources & webhook_resources and verbs & write_verbs:
            violations.append(Violation(
                rule_id="PG-RBAC-008",
                severity=Severity.HIGH,
                category=Category.RBAC,
                message=f"Role '{role.name}' can modify admission webhooks",
                resource_kind=role.kind,
                resource_name=role.name,
                namespace=role.namespace,
                file_path=role.file_path,
                suggestion="Restrict webhook modification to cluster admins only",
            ))
            break


def _check_default_sa_binding(binding, violations):
    """PG-RBAC-009: Binding to default service account."""
    subjects = binding.raw.get("subjects") or []
    for subj in subjects:
        if subj.get("kind") == "ServiceAccount" and subj.get("name") == "default":
            violations.append(Violation(
                rule_id="PG-RBAC-009",
                severity=Severity.HIGH,
                category=Category.RBAC,
                message=f"Binding '{binding.name}' grants permissions to default service account",
                resource_kind=binding.kind,
                resource_name=binding.name,
                namespace=binding.namespace,
                file_path=binding.file_path,
                suggestion="Create a dedicated service account instead of using 'default'",
                cis_id="5.1.5",
            ))
            break


def _check_cluster_admin_binding(binding, violations):
    """PG-RBAC-010: ClusterRoleBinding to cluster-admin."""
    role_ref = binding.raw.get("roleRef", {})
    if role_ref.get("name") == "cluster-admin":
        violations.append(Violation(
            rule_id="PG-RBAC-010",
            severity=Severity.CRITICAL,
            category=Category.RBAC,
            message=f"Binding '{binding.name}' grants cluster-admin privileges",
            resource_kind=binding.kind,
            resource_name=binding.name,
            namespace=binding.namespace,
            file_path=binding.file_path,
            suggestion="Use scoped roles instead of cluster-admin",
            cis_id="5.1.1",
        ))


def _check_all_groups_binding(binding, violations):
    """PG-RBAC-011: Binding to system:authenticated or system:unauthenticated."""
    subjects = binding.raw.get("subjects") or []
    for subj in subjects:
        group = subj.get("name", "")
        if subj.get("kind") == "Group" and group in ("system:authenticated", "system:unauthenticated"):
            sev = Severity.CRITICAL if group == "system:unauthenticated" else Severity.HIGH
            violations.append(Violation(
                rule_id="PG-RBAC-011",
                severity=sev,
                category=Category.RBAC,
                message=f"Binding '{binding.name}' grants permissions to '{group}' group",
                resource_kind=binding.kind,
                resource_name=binding.name,
                namespace=binding.namespace,
                file_path=binding.file_path,
                suggestion=f"Remove binding to '{group}' group — this is too broad",
            ))
