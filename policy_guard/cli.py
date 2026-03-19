"""policy-guard CLI — Kubernetes manifest security auditor."""
import sys
import os

import click
from rich.console import Console

from policy_guard import __version__
from policy_guard.models import AuditReport, Severity, Category, PolicyLevel
from policy_guard.parser import parse_manifests
from policy_guard.analyzers import pod_security, container_security, rbac_analyzer, workload_analyzer
from policy_guard.reporters.terminal_reporter import print_report
from policy_guard.reporters.export_reporter import export_json, export_html, export_sarif

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


console = Console()


def _run_audit(resources: list) -> list:
    """Run all analyzers and return combined violations."""
    violations = []
    violations.extend(pod_security.analyze(resources))
    violations.extend(container_security.analyze(resources))
    violations.extend(rbac_analyzer.analyze(resources))
    violations.extend(workload_analyzer.analyze(resources))
    return violations


@click.group()
@click.version_option(version=__version__, prog_name="policy-guard")
def main():
    """policy-guard — Kubernetes manifest security auditor.

    Audit Kubernetes YAML manifests against Pod Security Standards,
    CIS benchmarks, RBAC best practices, and container security rules.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show suggestions and CIS mappings")
@click.option("--format", "-f", "output_format", type=click.Choice(["terminal", "json", "html", "sarif"]), default="terminal")
@click.option("--output", "-o", "output_path", type=click.Path(), help="Output file path")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), help="Exit with code 1 if issues of this severity or above exist")
@click.option("--level", "-l", type=click.Choice(["privileged", "baseline", "restricted"]), default="restricted", help="Pod Security Standards level to enforce")
def scan(path, verbose, output_format, output_path, fail_on, level):
    """Scan Kubernetes manifests for security issues.

    PATH is a YAML file or directory containing Kubernetes manifests.
    """
    abs_path = os.path.abspath(path)
    resources = parse_manifests(abs_path)

    if not resources:
        console.print("[yellow]No Kubernetes resources found.[/yellow]")
        return

    violations = _run_audit(resources)

    # Filter by PSS level
    target_level = PolicyLevel(level)
    if target_level == PolicyLevel.PRIVILEGED:
        pass  # Show all
    elif target_level == PolicyLevel.BASELINE:
        violations = [v for v in violations if v.policy_level != PolicyLevel.RESTRICTED or v.policy_level is None]
    # RESTRICTED shows all (default)

    report = AuditReport(
        scan_path=abs_path,
        total_resources=len(resources),
        resources=resources,
        violations=violations,
        policy_level=target_level,
    )
    report.calculate_score()
    report.determine_compliance_level()

    if output_format == "json":
        dest = output_path or "policy-guard-report.json"
        export_json(report, dest)
        console.print(f"[green]JSON report saved to {dest}[/green]")
    elif output_format == "html":
        dest = output_path or "policy-guard-report.html"
        export_html(report, dest)
        console.print(f"[green]HTML report saved to {dest}[/green]")
    elif output_format == "sarif":
        dest = output_path or "policy-guard-report.sarif"
        export_sarif(report, dest)
        console.print(f"[green]SARIF report saved to {dest}[/green]")
    else:
        print_report(report, console, verbose)

    if fail_on:
        severity_levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold_idx = severity_levels.index(Severity(fail_on))
        triggered = [s for s in severity_levels[:threshold_idx + 1]]
        if any(v.severity in triggered for v in violations):
            raise SystemExit(1)


@main.command()
@click.option("--verbose", "-v", is_flag=True)
def demo(verbose):
    """Run a demo scan with sample insecure Kubernetes manifests.

    Creates a realistic production cluster with intentional security
    issues to demonstrate all policy-guard capabilities.
    """
    from policy_guard.demo import create_demo_manifests

    demo_dir = create_demo_manifests()
    console.print(f"[dim]  Demo manifests created in: {demo_dir}[/dim]\n")

    resources = parse_manifests(demo_dir)
    violations = _run_audit(resources)

    report = AuditReport(
        scan_path=demo_dir,
        total_resources=len(resources),
        resources=resources,
        violations=violations,
    )
    report.calculate_score()
    report.determine_compliance_level()

    print_report(report, console, verbose)


@main.command()
def rules():
    """List all security validation rules."""
    from rich.table import Table
    from policy_guard.models import SEVERITY_ICONS, SEVERITY_COLORS

    rule_defs = [
        # Pod Security Standards
        ("PG-PSS-001", "CRITICAL", "Pod Security", "Privileged container"),
        ("PG-PSS-002", "CRITICAL", "Pod Security", "Host PID namespace sharing"),
        ("PG-PSS-003", "CRITICAL", "Pod Security", "Host IPC namespace sharing"),
        ("PG-PSS-004", "CRITICAL", "Pod Security", "Host network usage"),
        ("PG-PSS-005", "CRITICAL", "Pod Security", "hostPath volume mount"),
        ("PG-PSS-006", "MEDIUM", "Pod Security", "hostPort usage"),
        ("PG-PSS-007", "HIGH", "Pod Security", "Dangerous Linux capabilities added"),
        ("PG-PSS-008", "MEDIUM", "Pod Security", "Capabilities not dropped (ALL)"),
        ("PG-PSS-009", "HIGH", "Pod Security", "Container may run as root"),
        ("PG-PSS-010", "HIGH", "Pod Security", "runAsUser set to 0 (root)"),
        ("PG-PSS-011", "MEDIUM", "Pod Security", "Missing seccomp profile"),
        ("PG-PSS-012", "MEDIUM", "Pod Security", "Non-standard AppArmor profile"),
        ("PG-PSS-013", "MEDIUM", "Pod Security", "Non-standard SELinux options"),
        ("PG-PSS-014", "HIGH", "Pod Security", "Non-default procMount"),
        ("PG-PSS-015", "HIGH", "Pod Security", "Unsafe sysctls"),
        ("PG-PSS-016", "MEDIUM", "Pod Security", "Restricted volume type"),
        ("PG-PSS-017", "HIGH", "Pod Security", "Privilege escalation allowed"),
        ("PG-PSS-018", "MEDIUM", "Pod Security", "Writable root filesystem"),
        ("PG-PSS-019", "MEDIUM", "Pod Security", "Default SA with auto-mounted token"),
        # Image Security
        ("PG-IMG-001", "HIGH", "Image Security", "Image uses latest/no tag"),
        ("PG-IMG-002", "LOW", "Image Security", "Image not pinned to digest"),
        ("PG-IMG-003", "MEDIUM", "Image Security", "Latest tag without Always pull policy"),
        ("PG-IMG-004", "MEDIUM", "Image Security", "Private registry without imagePullSecrets"),
        # Container Security
        ("PG-CTR-001", "MEDIUM", "Container", "Missing liveness probe"),
        ("PG-CTR-002", "MEDIUM", "Container", "Missing readiness probe"),
        ("PG-CTR-003", "HIGH", "Resource Mgmt", "No resource limits"),
        ("PG-CTR-004", "MEDIUM", "Resource Mgmt", "No resource requests"),
        ("PG-CTR-005", "LOW", "Resource Mgmt", "CPU limit too high (>4 cores)"),
        ("PG-CTR-006", "LOW", "Resource Mgmt", "Memory limit too high (>8Gi)"),
        ("PG-CTR-007", "HIGH", "Container", "Secrets in environment variables"),
        # RBAC
        ("PG-RBAC-001", "HIGH", "RBAC", "Wildcard resources access"),
        ("PG-RBAC-002", "HIGH", "RBAC", "Wildcard verbs"),
        ("PG-RBAC-003", "CRITICAL", "RBAC", "Write access to secrets"),
        ("PG-RBAC-004", "HIGH", "RBAC", "Pod exec/attach access"),
        ("PG-RBAC-005", "CRITICAL", "RBAC", "Escalation verbs (bind/escalate/impersonate)"),
        ("PG-RBAC-006", "CRITICAL", "RBAC", "Node proxy access"),
        ("PG-RBAC-007", "CRITICAL", "RBAC", "Cluster-admin equivalent permissions"),
        ("PG-RBAC-008", "HIGH", "RBAC", "Webhook modification access"),
        ("PG-RBAC-009", "HIGH", "RBAC", "Binding to default service account"),
        ("PG-RBAC-010", "CRITICAL", "RBAC", "Binding to cluster-admin"),
        ("PG-RBAC-011", "HIGH", "RBAC", "Binding to system:authenticated/unauthenticated"),
        # Workload & Network
        ("PG-WRK-001", "LOW", "Workload", "Single replica deployment"),
        ("PG-WRK-002", "LOW", "Workload", "No explicit update strategy"),
        ("PG-WRK-003", "MEDIUM", "Workload", "No PodDisruptionBudget"),
        ("PG-WRK-004", "INFO", "Workload", "No topology spread constraints"),
        ("PG-WRK-005", "INFO", "Workload", "No priorityClassName"),
        ("PG-WRK-006", "LOW", "Workload", "Short termination grace period"),
        ("PG-WRK-007", "INFO", "Workload", "No podAntiAffinity"),
        ("PG-NET-001", "HIGH", "Network", "LoadBalancer without sourceRanges"),
        ("PG-NET-002", "MEDIUM", "Network", "NodePort service"),
        ("PG-NET-003", "MEDIUM", "Network", "ExternalName service (SSRF vector)"),
        ("PG-NET-004", "HIGH", "Network", "Ingress without TLS"),
        ("PG-NET-005", "HIGH", "Network", "Dangerous Ingress annotations"),
    ]

    table = Table(title="📏 Security Validation Rules", show_lines=True, padding=(0, 1))
    table.add_column("Rule ID", style="bold cyan", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=16)
    table.add_column("Description", min_width=40)

    for rule_id, sev_str, category, desc in rule_defs:
        sev = Severity(sev_str.lower())
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        table.add_row(rule_id, f"[{color}]{icon} {sev_str}[/{color}]", category, desc)

    console.print()
    console.print(table)
    console.print(f"\n[dim]  {len(rule_defs)} validation rules across {len(set(c for _,_,c,_ in rule_defs))} categories[/dim]")
    console.print(f"[dim]  Covers: Pod Security Standards (Baseline+Restricted) | CIS K8s Benchmarks | RBAC | Network[/dim]\n")


if __name__ == "__main__":
    main()
