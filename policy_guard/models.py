"""Core data models for policy-guard."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PolicyLevel(Enum):
    """Pod Security Standards levels."""
    PRIVILEGED = "privileged"
    BASELINE = "baseline"
    RESTRICTED = "restricted"


class Category(Enum):
    """Rule categories."""
    POD_SECURITY = "Pod Security"
    CONTAINER = "Container Security"
    RBAC = "RBAC"
    WORKLOAD = "Workload"
    NETWORK = "Network Exposure"
    IMAGE = "Image Security"
    RESOURCE = "Resource Management"
    RELIABILITY = "Reliability"


SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

LEVEL_COLORS = {
    PolicyLevel.PRIVILEGED: "bright_red",
    PolicyLevel.BASELINE: "yellow",
    PolicyLevel.RESTRICTED: "green",
}

CATEGORY_ICONS = {
    Category.POD_SECURITY: "🛡️",
    Category.CONTAINER: "📦",
    Category.RBAC: "🔑",
    Category.WORKLOAD: "⚙️",
    Category.NETWORK: "🌐",
    Category.IMAGE: "🐳",
    Category.RESOURCE: "📊",
    Category.RELIABILITY: "💪",
}


@dataclass
class Violation:
    """A single policy violation."""
    rule_id: str
    severity: Severity
    category: Category
    message: str
    resource_kind: str
    resource_name: str
    namespace: str = "default"
    file_path: str = ""
    container_name: str = ""
    field_path: str = ""
    policy_level: Optional[PolicyLevel] = None
    suggestion: Optional[str] = None
    fix_yaml: Optional[str] = None
    cis_id: Optional[str] = None
    doc_url: Optional[str] = None


@dataclass
class Resource:
    """A parsed Kubernetes resource."""
    kind: str
    name: str
    namespace: str = "default"
    api_version: str = ""
    labels: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)
    spec: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    file_path: str = ""


@dataclass
class AuditReport:
    """Full audit report."""
    scan_path: str
    total_resources: int = 0
    resources: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    score: float = 100.0
    grade: str = "A+"
    policy_level: PolicyLevel = PolicyLevel.RESTRICTED
    compliant_level: Optional[PolicyLevel] = None

    @property
    def critical_count(self):
        return sum(1 for v in self.violations if v.severity == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for v in self.violations if v.severity == Severity.HIGH)

    @property
    def medium_count(self):
        return sum(1 for v in self.violations if v.severity == Severity.MEDIUM)

    @property
    def low_count(self):
        return sum(1 for v in self.violations if v.severity == Severity.LOW)

    @property
    def info_count(self):
        return sum(1 for v in self.violations if v.severity == Severity.INFO)

    def calculate_score(self):
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 6, Severity.LOW: 2, Severity.INFO: 0}
        total_deductions = sum(weights[v.severity] for v in self.violations)
        max_deduction = max(self.total_resources * 20, 80)
        self.score = max(0, round(100 - (total_deductions / max(max_deduction, 1)) * 100, 1))

        if self.score >= 95: self.grade = "A+"
        elif self.score >= 90: self.grade = "A"
        elif self.score >= 85: self.grade = "A-"
        elif self.score >= 80: self.grade = "B+"
        elif self.score >= 75: self.grade = "B"
        elif self.score >= 70: self.grade = "B-"
        elif self.score >= 65: self.grade = "C+"
        elif self.score >= 60: self.grade = "C"
        elif self.score >= 55: self.grade = "C-"
        elif self.score >= 50: self.grade = "D"
        elif self.score >= 40: self.grade = "D-"
        else: self.grade = "F"

    def determine_compliance_level(self):
        """Determine the highest PSS level that the resources comply with."""
        has_privileged_violations = any(
            v.policy_level == PolicyLevel.BASELINE for v in self.violations
        )
        has_baseline_violations = any(
            v.policy_level == PolicyLevel.RESTRICTED for v in self.violations
        )

        if not has_privileged_violations and not has_baseline_violations:
            self.compliant_level = PolicyLevel.RESTRICTED
        elif not has_privileged_violations:
            self.compliant_level = PolicyLevel.BASELINE
        else:
            self.compliant_level = PolicyLevel.PRIVILEGED
