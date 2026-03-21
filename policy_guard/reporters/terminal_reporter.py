"""Terminal reporter — rich terminal output for policy-guard."""
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule

from policy_guard.models import (
    AuditReport, Severity, Category, PolicyLevel,
    SEVERITY_COLORS, SEVERITY_ICONS, LEVEL_COLORS, CATEGORY_ICONS,
)


GRADE_COLORS = {
    "A+": "bright_green", "A": "green", "A-": "green",
    "B+": "bright_yellow", "B": "yellow", "B-": "yellow",
    "C+": "dark_orange", "C": "dark_orange", "C-": "dark_orange",
    "D": "red", "D-": "red",
    "F": "bright_red",
}

BANNER = r"""[bright_cyan]
                _ _                                       _
  _ __   ___  | (_) ___ _   _        __ _ _   _  __ _ _ __| |
 | '_ \ / _ \ | | |/ __| | | |_____ / _` | | | |/ _` | '__| |
 | |_) | (_) || | | (__| |_| |_____| (_| | |_| | (_| | |  |_|
 | .__/ \___/ |_|_|\___|\__, |      \__, |\__,_|\__,_|_|  (_)
 |_|                    |___/       |___/
[/bright_cyan]
[dim]  Kubernetes Manifest Security Auditor[/dim]
[dim]  v1.0.0 — 75+ rules | Pod Security Standards | CIS Benchmarks | RBAC[/dim]
"""


def print_report(report: AuditReport, console: Console, verbose: bool = False):
    console.print(BANNER)
    console.print()
    _print_overview(report, console)
    console.print()
    _print_score(report, console)
    console.print()
    _print_pss_compliance(report, console)
    console.print()
    _print_severity_summary(report, console)
    console.print()
    _print_category_summary(report, console)
    console.print()
    if report.violations:
        _print_violations(report, console, verbose)
        console.print()
    _print_recommendations(report, console)
    console.print()
    _print_footer(report, console)


def _print_overview(report, console):
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column()

    info.add_row("Scan Path:", report.scan_path)
    info.add_row("Resources Found:", str(report.total_resources))

    kinds = Counter(r.kind for r in report.resources)
    kind_str = ", ".join(f"{k}:{v}" for k, v in kinds.most_common(8))
    info.add_row("Resource Types:", kind_str or "none")

    namespaces = set(r.namespace for r in report.resources)
    info.add_row("Namespaces:", ", ".join(sorted(namespaces)) if namespaces else "none")

    panel = Panel(info, title="📋 Scan Overview", border_style="cyan", padding=(1, 2))
    console.print(panel)


def _print_score(report, console):
    grade_color = GRADE_COLORS.get(report.grade, "white")

    score_text = Text()
    score_text.append("  Security Score: ", style="bold")
    score_text.append(f"{report.score}", style=f"bold {grade_color}")
    score_text.append(" / 100", style="dim")
    score_text.append("    Grade: ", style="bold")
    score_text.append(f" {report.grade} ", style=f"bold white on {grade_color}")

    bar_width = 40
    filled = int(report.score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    bar_text = Text()
    bar_text.append("  [", style="dim")
    bar_text.append(bar[:filled], style=grade_color)
    bar_text.append(bar[filled:], style="dim")
    bar_text.append("]", style="dim")

    panel_content = Text()
    panel_content.append_text(score_text)
    panel_content.append("\n")
    panel_content.append_text(bar_text)

    panel = Panel(panel_content, title="🛡️ Security Score", border_style=grade_color, padding=(1, 2))
    console.print(panel)


def _print_pss_compliance(report, console):
    if not report.compliant_level:
        return

    level = report.compliant_level
    color = LEVEL_COLORS.get(level, "white")

    levels_info = Text()
    for lvl in PolicyLevel:
        is_current = (lvl == level)
        lvl_color = LEVEL_COLORS[lvl]
        marker = "●" if is_current else "○"
        style = f"bold {lvl_color}" if is_current else "dim"
        levels_info.append(f"  {marker} {lvl.value.upper()}  ", style=style)

    panel = Panel(
        levels_info,
        title=f"🔐 Pod Security Standards — Compliant Level: {level.value.upper()}",
        border_style=color,
        padding=(1, 2),
    )
    console.print(panel)


def _print_severity_summary(report, console):
    table = Table(title="Issues by Severity", box=None, padding=(0, 3), show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Bar", min_width=30)

    counts = {
        Severity.CRITICAL: report.critical_count,
        Severity.HIGH: report.high_count,
        Severity.MEDIUM: report.medium_count,
        Severity.LOW: report.low_count,
        Severity.INFO: report.info_count,
    }

    max_count = max(counts.values()) if any(counts.values()) else 1

    for sev, count in counts.items():
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        bar_len = int(count / max(max_count, 1) * 25) if count > 0 else 0
        bar = "█" * bar_len

        table.add_row(
            f"{icon} {sev.value.upper()}",
            f"[{color}]{count}[/{color}]",
            f"[{color}]{bar}[/{color}]",
        )

    console.print(table)


def _print_category_summary(report, console):
    cat_counts = Counter(v.category for v in report.violations)

    table = Table(title="Issues by Category", box=None, padding=(0, 3))
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Bar", min_width=25)

    max_count = max(cat_counts.values()) if cat_counts else 1

    for cat in Category:
        count = cat_counts.get(cat, 0)
        if count == 0:
            continue
        icon = CATEGORY_ICONS.get(cat, "")
        bar_len = int(count / max(max_count, 1) * 20) if count > 0 else 0
        bar = "█" * bar_len
        table.add_row(f"{icon} {cat.value}", str(count), f"[cyan]{bar}[/cyan]")

    if cat_counts:
        console.print(table)


def _print_violations(report, console, verbose):
    severity_order = list(Severity)
    sorted_violations = sorted(report.violations, key=lambda v: severity_order.index(v.severity))

    table = Table(
        title=f"🔍 Violations Found ({len(report.violations)})",
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Rule", style="bold cyan", width=14)
    table.add_column("Sev", width=5, justify="center")
    table.add_column("Resource", width=30)
    table.add_column("Message", min_width=45)

    if verbose:
        table.add_column("Fix", style="italic green", min_width=30)

    max_display = 40 if not verbose else len(sorted_violations)

    for v in sorted_violations[:max_display]:
        sev_color = SEVERITY_COLORS[v.severity]
        sev_icon = SEVERITY_ICONS[v.severity]
        resource = f"{v.resource_kind}/{v.resource_name}"
        if v.container_name:
            resource += f"\n  → {v.container_name}"

        row = [
            v.rule_id,
            f"[{sev_color}]{sev_icon}[/{sev_color}]",
            resource,
            f"[{sev_color}]{v.message}[/{sev_color}]",
        ]

        if verbose:
            fix = v.suggestion or ""
            if v.cis_id:
                fix += f"\n[dim]CIS: {v.cis_id}[/dim]"
            row.append(fix)

        table.add_row(*row)

    if len(sorted_violations) > max_display:
        console.print(f"\n  [dim]... and {len(sorted_violations) - max_display} more. Use --verbose to see all.[/dim]")

    console.print(table)


def _print_recommendations(report, console):
    if not report.violations:
        console.print(Panel(
            "[bright_green]✨ All resources pass security checks! Excellent hardening.[/bright_green]",
            title="🎉 Perfect Score",
            border_style="bright_green",
        ))
        return

    priority = [v for v in report.violations if v.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not priority:
        priority = [v for v in report.violations if v.severity == Severity.MEDIUM]

    recs = []
    seen = set()
    for v in priority[:5]:
        if v.suggestion and v.suggestion not in seen:
            seen.add(v.suggestion)
            sev_icon = SEVERITY_ICONS[v.severity]
            sev_color = SEVERITY_COLORS[v.severity]
            recs.append(f"  [{sev_color}]{sev_icon} [{v.rule_id}][/{sev_color}] {v.suggestion}")

    if recs:
        console.print(Panel(
            "\n".join(recs),
            title="💡 Top Recommendations",
            border_style="yellow",
            padding=(1, 2),
        ))


def _print_footer(report, console):
    console.print(Rule(style="dim"))
    total = len(report.violations)
    if total == 0:
        console.print("[bright_green]  ✅ All resources pass security checks.[/bright_green]")
    elif report.critical_count > 0:
        console.print(f"[bright_red]  ⛔ {report.critical_count} critical security issue(s) must be fixed immediately.[/bright_red]")
    elif report.high_count > 0:
        console.print(f"[red]  ⚠️  {report.high_count} high-severity issue(s) need attention.[/red]")
    else:
        console.print(f"[yellow]  💡 {total} suggestion(s) to improve security posture.[/yellow]")

    console.print("[dim]  policy-guard v1.0.0 | 50+ rules | PSS + CIS + RBAC | Made with ❤️  for K8s security[/dim]")
    console.print()
