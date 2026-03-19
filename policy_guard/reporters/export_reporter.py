"""JSON, HTML, and SARIF export reporters for policy-guard."""
import json
from datetime import datetime, timezone
from collections import Counter

from policy_guard.models import AuditReport, Severity, Category, PolicyLevel


def export_json(report: AuditReport, output_path: str):
    data = {
        "tool": "policy-guard",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_path": report.scan_path,
        "score": report.score,
        "grade": report.grade,
        "compliant_level": report.compliant_level.value if report.compliant_level else None,
        "summary": {
            "total_resources": report.total_resources,
            "total_violations": len(report.violations),
            "by_severity": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
            "by_category": {
                cat.value: sum(1 for v in report.violations if v.category == cat)
                for cat in Category
            },
        },
        "violations": [
            {
                "rule_id": v.rule_id,
                "severity": v.severity.value,
                "category": v.category.value,
                "message": v.message,
                "resource": f"{v.resource_kind}/{v.resource_name}",
                "namespace": v.namespace,
                "container": v.container_name,
                "field_path": v.field_path,
                "policy_level": v.policy_level.value if v.policy_level else None,
                "suggestion": v.suggestion,
                "fix_yaml": v.fix_yaml,
                "cis_id": v.cis_id,
                "file": v.file_path,
            }
            for v in report.violations
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_sarif(report: AuditReport, output_path: str):
    """Export in SARIF format for GitHub Security tab integration."""
    rules = {}
    results = []

    for v in report.violations:
        if v.rule_id not in rules:
            sarif_level = {
                "critical": "error", "high": "error",
                "medium": "warning", "low": "note", "info": "note",
            }
            rules[v.rule_id] = {
                "id": v.rule_id,
                "shortDescription": {"text": v.message[:100]},
                "defaultConfiguration": {
                    "level": sarif_level.get(v.severity.value, "warning"),
                },
                "helpUri": v.doc_url or "",
            }

        result = {
            "ruleId": v.rule_id,
            "level": "error" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
            "message": {"text": v.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": v.file_path.replace("\\", "/")},
                    },
                    "logicalLocations": [
                        {"name": f"{v.resource_kind}/{v.resource_name}", "kind": "resource"},
                    ],
                }
            ],
        }
        if v.suggestion:
            result["fixes"] = [{"description": {"text": v.suggestion}}]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "policy-guard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/SanjaySundarMurthy/policy-guard",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)


def export_html(report: AuditReport, output_path: str):
    sev_colors = {
        "critical": "#ef4444", "high": "#f97316",
        "medium": "#eab308", "low": "#06b6d4", "info": "#6b7280",
    }

    grade_color = {
        "A+": "#22c55e", "A": "#22c55e", "A-": "#22c55e",
        "B+": "#eab308", "B": "#eab308", "B-": "#eab308",
        "C+": "#f97316", "C": "#f97316", "C-": "#f97316",
        "D": "#ef4444", "D-": "#ef4444", "F": "#dc2626",
    }.get(report.grade, "#fff")

    violations_html = ""
    severity_order = list(Severity)
    sorted_v = sorted(report.violations, key=lambda v: severity_order.index(v.severity))
    for v in sorted_v:
        sc = sev_colors.get(v.severity.value, "#fff")
        fix_html = f'<div class="fix">{v.suggestion}</div>' if v.suggestion else ""
        cis_html = f'<span class="cis">CIS {v.cis_id}</span>' if v.cis_id else ""
        violations_html += f"""
        <tr>
          <td style="color:{sc};font-weight:bold">{v.rule_id}</td>
          <td><span class="badge" style="background:{sc}">{v.severity.value.upper()}</span></td>
          <td>{v.resource_kind}/{v.resource_name}</td>
          <td>{v.message}{fix_html}{cis_html}</td>
        </tr>"""

    cat_counts = Counter(v.category.value for v in report.violations)
    cats_html = ""
    for cat in Category:
        count = cat_counts.get(cat.value, 0)
        if count:
            cats_html += f'<div class="cat-item"><span>{cat.value}</span><span class="cat-count">{count}</span></div>'

    pss_level = report.compliant_level.value.upper() if report.compliant_level else "N/A"
    pss_color = {"PRIVILEGED": "#ef4444", "BASELINE": "#eab308", "RESTRICTED": "#22c55e"}.get(pss_level, "#fff")

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>policy-guard Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
.container{{max-width:1200px;margin:0 auto}}
h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:.5rem}}
.subtitle{{color:#8b949e;margin-bottom:2rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-bottom:2rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem}}
.card h3{{color:#8b949e;font-size:.85rem;text-transform:uppercase;margin-bottom:.5rem}}
.big-number{{font-size:2.5rem;font-weight:bold}}
.badge{{padding:2px 8px;border-radius:4px;color:#fff;font-size:.75rem;font-weight:bold}}
table{{width:100%;border-collapse:collapse;margin-top:1rem}}
th,td{{padding:.75rem;text-align:left;border-bottom:1px solid #21262d}}
th{{color:#8b949e;font-size:.85rem;text-transform:uppercase}}
.fix{{color:#22c55e;font-style:italic;font-size:.85rem;margin-top:.25rem}}
.cis{{color:#8b949e;font-size:.75rem;margin-left:.5rem}}
.cat-item{{display:flex;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid #21262d}}
.cat-count{{color:#58a6ff;font-weight:bold}}
.pss-badge{{display:inline-block;padding:4px 12px;border-radius:4px;color:#fff;font-weight:bold}}
</style></head>
<body><div class="container">
<h1>🛡️ policy-guard Security Report</h1>
<p class="subtitle">Kubernetes Manifest Security Audit — {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>

<div class="grid">
  <div class="card"><h3>Security Score</h3><div class="big-number" style="color:{grade_color}">{report.score}<span style="font-size:1rem;color:#8b949e"> / 100</span></div><div style="margin-top:.5rem"><span class="badge" style="background:{grade_color};font-size:1.2rem;padding:4px 12px">Grade: {report.grade}</span></div></div>
  <div class="card"><h3>PSS Compliance</h3><div style="margin-top:.5rem"><span class="pss-badge" style="background:{pss_color}">{pss_level}</span></div></div>
  <div class="card"><h3>Resources Scanned</h3><div class="big-number" style="color:#58a6ff">{report.total_resources}</div></div>
  <div class="card"><h3>Total Violations</h3><div class="big-number" style="color:#f97316">{len(report.violations)}</div></div>
</div>

<div class="grid">
  <div class="card"><h3>By Severity</h3>
    <div class="cat-item"><span><span class="badge" style="background:#ef4444">CRITICAL</span></span><span>{report.critical_count}</span></div>
    <div class="cat-item"><span><span class="badge" style="background:#f97316">HIGH</span></span><span>{report.high_count}</span></div>
    <div class="cat-item"><span><span class="badge" style="background:#eab308">MEDIUM</span></span><span>{report.medium_count}</span></div>
    <div class="cat-item"><span><span class="badge" style="background:#06b6d4">LOW</span></span><span>{report.low_count}</span></div>
    <div class="cat-item"><span><span class="badge" style="background:#6b7280">INFO</span></span><span>{report.info_count}</span></div>
  </div>
  <div class="card"><h3>By Category</h3>{cats_html}</div>
</div>

<div class="card" style="margin-top:1rem">
<h3>Violations ({len(report.violations)})</h3>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Resource</th><th>Details</th></tr></thead>
<tbody>{violations_html}</tbody></table>
</div>

<p style="text-align:center;color:#8b949e;margin-top:2rem;font-size:.85rem">
Generated by policy-guard v1.0.0 | 75+ rules | PSS + CIS + RBAC
</p>
</div></body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
