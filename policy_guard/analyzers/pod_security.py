"""Pod Security Standards analyzer — checks against Privileged, Baseline, and Restricted levels.

Rules PG-PSS-001 through PG-PSS-025.
Based on: https://kubernetes.io/docs/concepts/security/pod-security-standards/
"""
from policy_guard.models import Violation, Severity, Category, PolicyLevel, Resource
from policy_guard.parser import get_pod_spec, get_containers

# Linux capabilities that must be dropped in Restricted level
RESTRICTED_DROP_CAPS = {"ALL"}
# Capabilities that may be added in Restricted level
RESTRICTED_ALLOW_CAPS = {"NET_BIND_SERVICE"}
# Dangerous capabilities
DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID",
    "NET_RAW", "SYS_RAWIO", "SYS_CHROOT", "KILL",
    "MKNOD", "AUDIT_WRITE", "SYS_RESOURCE",
}

# Disallowed volume types for Baseline
BASELINE_DISALLOWED_VOLUMES = {
    "hostPath",
}

# Disallowed volume types for Restricted (only these are allowed)
RESTRICTED_ALLOWED_VOLUMES = {
    "configMap", "csi", "downwardAPI", "emptyDir",
    "ephemeral", "persistentVolumeClaim", "projected", "secret",
}

# Dangerous host paths
DANGEROUS_HOST_PATHS = {
    "/", "/etc", "/var", "/proc", "/sys", "/dev",
    "/var/run/docker.sock", "/run/containerd",
    "/var/lib/kubelet", "/etc/kubernetes",
}

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def analyze(resources: list) -> list:
    violations = []
    for res in resources:
        if res.kind not in WORKLOAD_KINDS:
            continue
        pod_spec = get_pod_spec(res)
        if not pod_spec:
            continue
        containers = get_containers(res)

        _check_privileged(res, containers, violations)
        _check_host_namespaces(res, pod_spec, violations)
        _check_host_paths(res, pod_spec, violations)
        _check_host_ports(res, containers, violations)
        _check_capabilities(res, containers, violations)
        _check_run_as_non_root(res, pod_spec, containers, violations)
        _check_run_as_user(res, pod_spec, containers, violations)
        _check_seccomp_profile(res, pod_spec, containers, violations)
        _check_apparmor(res, pod_spec, containers, violations)
        _check_selinux(res, pod_spec, containers, violations)
        _check_proc_mount(res, containers, violations)
        _check_sysctls(res, pod_spec, violations)
        _check_volume_types(res, pod_spec, violations)
        _check_privilege_escalation(res, containers, violations)
        _check_read_only_root(res, containers, violations)
        _check_service_account(res, pod_spec, violations)

    return violations


def _check_privileged(res, containers, violations):
    """PG-PSS-001: Privileged containers."""
    for c in containers:
        sc = c.get("securityContext", {}) or {}
        if sc.get("privileged"):
            violations.append(Violation(
                rule_id="PG-PSS-001",
                severity=Severity.CRITICAL,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' runs as privileged",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.privileged",
                policy_level=PolicyLevel.BASELINE,
                suggestion="Set securityContext.privileged to false",
                fix_yaml="securityContext:\n  privileged: false",
                cis_id="5.2.1",
            ))


def _check_host_namespaces(res, pod_spec, violations):
    """PG-PSS-002/003/004: hostPID, hostIPC, hostNetwork."""
    checks = [
        ("hostPID", "PG-PSS-002", "shares host PID namespace"),
        ("hostIPC", "PG-PSS-003", "shares host IPC namespace"),
        ("hostNetwork", "PG-PSS-004", "uses host networking"),
    ]
    for field_name, rule_id, desc in checks:
        if pod_spec.get(field_name):
            violations.append(Violation(
                rule_id=rule_id,
                severity=Severity.CRITICAL,
                category=Category.POD_SECURITY,
                message=f"{res.kind}/{res.name} {desc}",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                field_path=f"spec.{field_name}",
                policy_level=PolicyLevel.BASELINE,
                suggestion=f"Set {field_name} to false",
                cis_id="5.2.2" if field_name == "hostPID" else "5.2.3",
            ))


def _check_host_paths(res, pod_spec, violations):
    """PG-PSS-005: hostPath volumes."""
    for vol in (pod_spec.get("volumes") or []):
        hp = vol.get("hostPath")
        if hp:
            path = hp.get("path", "")
            sev = Severity.CRITICAL if path in DANGEROUS_HOST_PATHS else Severity.HIGH
            violations.append(Violation(
                rule_id="PG-PSS-005",
                severity=sev,
                category=Category.POD_SECURITY,
                message=f"Volume '{vol.get('name', '?')}' mounts hostPath '{path}'",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                field_path=f"spec.volumes[].hostPath.path",
                policy_level=PolicyLevel.BASELINE,
                suggestion="Replace hostPath volumes with emptyDir, PVC, or configMap",
                cis_id="5.2.13",
            ))


def _check_host_ports(res, containers, violations):
    """PG-PSS-006: hostPort usage."""
    for c in containers:
        for port in (c.get("ports") or []):
            hp = port.get("hostPort")
            if hp and hp > 0:
                violations.append(Violation(
                    rule_id="PG-PSS-006",
                    severity=Severity.MEDIUM,
                    category=Category.POD_SECURITY,
                    message=f"Container '{c.get('name', '?')}' uses hostPort {hp}",
                    resource_kind=res.kind,
                    resource_name=res.name,
                    namespace=res.namespace,
                    file_path=res.file_path,
                    container_name=c.get("name", ""),
                    field_path="spec.containers[].ports[].hostPort",
                    policy_level=PolicyLevel.BASELINE,
                    suggestion="Use a Service or NodePort instead of hostPort",
                ))


def _check_capabilities(res, containers, violations):
    """PG-PSS-007/008: Linux capabilities."""
    for c in containers:
        sc = c.get("securityContext", {}) or {}
        caps = sc.get("capabilities", {}) or {}
        adds = set(caps.get("add") or [])
        drops = set(caps.get("drop") or [])

        # Baseline: must not add dangerous capabilities
        for cap in adds:
            cap_upper = cap.upper()
            if cap_upper in DANGEROUS_CAPS:
                violations.append(Violation(
                    rule_id="PG-PSS-007",
                    severity=Severity.HIGH,
                    category=Category.POD_SECURITY,
                    message=f"Container '{c.get('name', '?')}' adds dangerous capability {cap_upper}",
                    resource_kind=res.kind,
                    resource_name=res.name,
                    namespace=res.namespace,
                    file_path=res.file_path,
                    container_name=c.get("name", ""),
                    field_path="spec.containers[].securityContext.capabilities.add",
                    policy_level=PolicyLevel.BASELINE,
                    suggestion=f"Remove {cap_upper} from capabilities.add",
                    cis_id="5.2.7",
                ))

        # Restricted: must drop ALL
        if "ALL" not in drops:
            violations.append(Violation(
                rule_id="PG-PSS-008",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' does not drop ALL capabilities",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.capabilities.drop",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Add 'capabilities: {drop: [ALL]}' to securityContext",
                fix_yaml="securityContext:\n  capabilities:\n    drop: [ALL]",
                cis_id="5.2.7",
            ))

        # Restricted: only NET_BIND_SERVICE may be added
        for cap in adds:
            if cap.upper() not in RESTRICTED_ALLOW_CAPS:
                violations.append(Violation(
                    rule_id="PG-PSS-008",
                    severity=Severity.MEDIUM,
                    category=Category.POD_SECURITY,
                    message=f"Container '{c.get('name', '?')}' adds capability {cap.upper()} (only NET_BIND_SERVICE allowed in Restricted)",
                    resource_kind=res.kind,
                    resource_name=res.name,
                    namespace=res.namespace,
                    file_path=res.file_path,
                    container_name=c.get("name", ""),
                    policy_level=PolicyLevel.RESTRICTED,
                ))


def _check_run_as_non_root(res, pod_spec, containers, violations):
    """PG-PSS-009: runAsNonRoot."""
    pod_sc = pod_spec.get("securityContext", {}) or {}
    pod_non_root = pod_sc.get("runAsNonRoot")

    for c in containers:
        sc = c.get("securityContext", {}) or {}
        c_non_root = sc.get("runAsNonRoot")
        c_run_as_user = sc.get("runAsUser")

        # Effective value: container overrides pod
        effective = c_non_root if c_non_root is not None else pod_non_root

        if effective is not True and (c_run_as_user is None or c_run_as_user == 0):
            violations.append(Violation(
                rule_id="PG-PSS-009",
                severity=Severity.HIGH,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' may run as root (runAsNonRoot not set)",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.runAsNonRoot",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set runAsNonRoot: true in securityContext",
                fix_yaml="securityContext:\n  runAsNonRoot: true",
                cis_id="5.2.6",
            ))


def _check_run_as_user(res, pod_spec, containers, violations):
    """PG-PSS-010: runAsUser = 0 (root)."""
    pod_sc = pod_spec.get("securityContext", {}) or {}
    pod_uid = pod_sc.get("runAsUser")

    if pod_uid == 0:
        violations.append(Violation(
            rule_id="PG-PSS-010",
            severity=Severity.HIGH,
            category=Category.POD_SECURITY,
            message=f"Pod spec runAsUser is 0 (root)",
            resource_kind=res.kind,
            resource_name=res.name,
            namespace=res.namespace,
            file_path=res.file_path,
            field_path="spec.securityContext.runAsUser",
            policy_level=PolicyLevel.RESTRICTED,
            suggestion="Set runAsUser to a non-zero value (e.g., 1000)",
            cis_id="5.2.6",
        ))

    for c in containers:
        sc = c.get("securityContext", {}) or {}
        uid = sc.get("runAsUser")
        if uid == 0:
            violations.append(Violation(
                rule_id="PG-PSS-010",
                severity=Severity.HIGH,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' runs as UID 0 (root)",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.runAsUser",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set runAsUser to a non-zero value",
                cis_id="5.2.6",
            ))


def _check_seccomp_profile(res, pod_spec, containers, violations):
    """PG-PSS-011: Seccomp profile must be RuntimeDefault or Localhost."""
    pod_sc = pod_spec.get("securityContext", {}) or {}
    pod_seccomp = pod_sc.get("seccompProfile", {}) or {}
    pod_type = pod_seccomp.get("type", "")

    for c in containers:
        sc = c.get("securityContext", {}) or {}
        c_seccomp = sc.get("seccompProfile", {}) or {}
        c_type = c_seccomp.get("type", "")

        effective_type = c_type or pod_type

        if effective_type not in ("RuntimeDefault", "Localhost"):
            violations.append(Violation(
                rule_id="PG-PSS-011",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' missing seccomp profile (have: '{effective_type or 'none'}')",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.securityContext.seccompProfile",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set seccompProfile.type to RuntimeDefault",
                fix_yaml="securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
                cis_id="5.7.2",
            ))


def _check_apparmor(res, pod_spec, containers, violations):
    """PG-PSS-012: AppArmor profile."""
    annotations = res.annotations
    for c in containers:
        c_name = c.get("name", "")
        key = f"container.apparmor.security.beta.kubernetes.io/{c_name}"
        profile = annotations.get(key, "")
        if profile and profile not in ("runtime/default", "localhost/"):
            if not profile.startswith("localhost/"):
                violations.append(Violation(
                    rule_id="PG-PSS-012",
                    severity=Severity.MEDIUM,
                    category=Category.POD_SECURITY,
                    message=f"Container '{c_name}' has non-standard AppArmor profile: {profile}",
                    resource_kind=res.kind,
                    resource_name=res.name,
                    namespace=res.namespace,
                    file_path=res.file_path,
                    container_name=c_name,
                    policy_level=PolicyLevel.BASELINE,
                ))


def _check_selinux(res, pod_spec, containers, violations):
    """PG-PSS-013: SELinux options."""
    ALLOWED_TYPES = {"", "container_t", "container_init_t", "container_kvm_t"}

    def check_opts(sc, context_name):
        se = (sc.get("seLinuxOptions") or {})
        se_type = se.get("type", "")
        if se_type and se_type not in ALLOWED_TYPES:
            violations.append(Violation(
                rule_id="PG-PSS-013",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"{context_name} uses non-standard SELinux type: {se_type}",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                policy_level=PolicyLevel.BASELINE,
            ))

    pod_sc = pod_spec.get("securityContext", {}) or {}
    check_opts(pod_sc, "Pod spec")

    for c in containers:
        sc = c.get("securityContext", {}) or {}
        check_opts(sc, f"Container '{c.get('name', '?')}'")


def _check_proc_mount(res, containers, violations):
    """PG-PSS-014: procMount must be Default."""
    for c in containers:
        sc = c.get("securityContext", {}) or {}
        pm = sc.get("procMount", "Default")
        if pm != "Default":
            violations.append(Violation(
                rule_id="PG-PSS-014",
                severity=Severity.HIGH,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' has procMount={pm} (must be Default)",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                policy_level=PolicyLevel.BASELINE,
                suggestion="Set procMount to 'Default' or remove it",
            ))


def _check_sysctls(res, pod_spec, violations):
    """PG-PSS-015: Unsafe sysctls."""
    SAFE_SYSCTLS = {
        "kernel.shm_rmid_forced",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_unprivileged_port_start",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ping_group_range",
    }

    for sysctl in (pod_spec.get("securityContext", {}) or {}).get("sysctls", []) or []:
        name = sysctl.get("name", "")
        if name not in SAFE_SYSCTLS:
            violations.append(Violation(
                rule_id="PG-PSS-015",
                severity=Severity.HIGH,
                category=Category.POD_SECURITY,
                message=f"Unsafe sysctl '{name}' used",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                policy_level=PolicyLevel.BASELINE,
                suggestion=f"Remove sysctl '{name}' or use a safe alternative",
            ))


def _check_volume_types(res, pod_spec, violations):
    """PG-PSS-016: Restricted volume types."""
    for vol in (pod_spec.get("volumes") or []):
        vol_type = None
        for key in vol:
            if key != "name":
                vol_type = key
                break
        if vol_type and vol_type not in RESTRICTED_ALLOWED_VOLUMES:
            violations.append(Violation(
                rule_id="PG-PSS-016",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"Volume '{vol.get('name', '?')}' uses type '{vol_type}' (not in restricted allow-list)",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                policy_level=PolicyLevel.RESTRICTED,
                suggestion=f"Use one of: {', '.join(sorted(RESTRICTED_ALLOWED_VOLUMES))}",
            ))


def _check_privilege_escalation(res, containers, violations):
    """PG-PSS-017: allowPrivilegeEscalation must be false."""
    for c in containers:
        sc = c.get("securityContext", {}) or {}
        if sc.get("allowPrivilegeEscalation", True) is not False:
            violations.append(Violation(
                rule_id="PG-PSS-017",
                severity=Severity.HIGH,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' allows privilege escalation",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.allowPrivilegeEscalation",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set allowPrivilegeEscalation: false",
                fix_yaml="securityContext:\n  allowPrivilegeEscalation: false",
                cis_id="5.2.5",
            ))


def _check_read_only_root(res, containers, violations):
    """PG-PSS-018: readOnlyRootFilesystem."""
    for c in containers:
        sc = c.get("securityContext", {}) or {}
        if not sc.get("readOnlyRootFilesystem"):
            violations.append(Violation(
                rule_id="PG-PSS-018",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"Container '{c.get('name', '?')}' has writable root filesystem",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                container_name=c.get("name", ""),
                field_path="spec.containers[].securityContext.readOnlyRootFilesystem",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set readOnlyRootFilesystem: true",
                fix_yaml="securityContext:\n  readOnlyRootFilesystem: true",
                cis_id="5.2.4",
            ))


def _check_service_account(res, pod_spec, violations):
    """PG-PSS-019: automountServiceAccountToken."""
    if pod_spec.get("automountServiceAccountToken", True) is not False:
        sa = pod_spec.get("serviceAccountName", "default")
        if sa == "default":
            violations.append(Violation(
                rule_id="PG-PSS-019",
                severity=Severity.MEDIUM,
                category=Category.POD_SECURITY,
                message=f"Uses default service account with auto-mounted token",
                resource_kind=res.kind,
                resource_name=res.name,
                namespace=res.namespace,
                file_path=res.file_path,
                field_path="spec.automountServiceAccountToken",
                policy_level=PolicyLevel.RESTRICTED,
                suggestion="Set automountServiceAccountToken: false or use a dedicated service account",
                cis_id="5.1.5",
            ))
