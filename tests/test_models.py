"""Tests for policy-guard data models."""
from policy_guard.models import (
    Severity, PolicyLevel, Category,
    Violation, Resource, AuditReport,
)


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_policy_level_values(self):
        assert PolicyLevel.PRIVILEGED.value == "privileged"
        assert PolicyLevel.BASELINE.value == "baseline"
        assert PolicyLevel.RESTRICTED.value == "restricted"

    def test_category_values(self):
        assert Category.POD_SECURITY.value == "Pod Security"
        assert Category.RBAC.value == "RBAC"


class TestViolation:
    def test_create_violation(self):
        v = Violation(
            rule_id="PG-PSS-001",
            severity=Severity.CRITICAL,
            category=Category.POD_SECURITY,
            message="Privileged container",
            resource_kind="Deployment",
            resource_name="test",
        )
        assert v.rule_id == "PG-PSS-001"
        assert v.severity == Severity.CRITICAL
        assert v.namespace == "default"

    def test_violation_with_fix(self):
        v = Violation(
            rule_id="PG-PSS-017",
            severity=Severity.HIGH,
            category=Category.POD_SECURITY,
            message="Privilege escalation",
            resource_kind="Deployment",
            resource_name="test",
            fix_yaml="allowPrivilegeEscalation: false",
            cis_id="5.2.5",
        )
        assert v.fix_yaml is not None
        assert v.cis_id == "5.2.5"


class TestResource:
    def test_create_resource(self):
        r = Resource(kind="Deployment", name="web")
        assert r.kind == "Deployment"
        assert r.namespace == "default"
        assert r.labels == {}
        assert r.spec == {}

    def test_resource_with_full_fields(self):
        r = Resource(
            kind="Pod",
            name="test",
            namespace="production",
            api_version="v1",
            labels={"app": "test"},
            spec={"containers": [{"name": "app"}]},
        )
        assert r.namespace == "production"
        assert r.api_version == "v1"


class TestAuditReport:
    def test_empty_report(self):
        report = AuditReport(scan_path="/tmp/test")
        assert report.score == 100.0
        assert report.grade == "A+"
        assert report.critical_count == 0

    def test_severity_counts(self):
        violations = [
            Violation("PG-PSS-001", Severity.CRITICAL, Category.POD_SECURITY, "crit", "Deploy", "a"),
            Violation("PG-PSS-002", Severity.CRITICAL, Category.POD_SECURITY, "crit2", "Deploy", "a"),
            Violation("PG-CTR-001", Severity.MEDIUM, Category.CONTAINER, "med", "Deploy", "a"),
        ]
        report = AuditReport(scan_path="/tmp", violations=violations)
        assert report.critical_count == 2
        assert report.medium_count == 1

    def test_calculate_score(self):
        violations = [
            Violation("PG-PSS-001", Severity.CRITICAL, Category.POD_SECURITY, "crit", "Deploy", "a"),
        ]
        report = AuditReport(scan_path="/tmp", total_resources=3, violations=violations)
        report.calculate_score()
        assert report.score < 100

    def test_perfect_score(self):
        report = AuditReport(scan_path="/tmp", total_resources=5)
        report.calculate_score()
        assert report.score == 100.0
        assert report.grade == "A+"

    def test_determine_compliance_level_restricted(self):
        report = AuditReport(scan_path="/tmp", total_resources=1)
        report.determine_compliance_level()
        assert report.compliant_level == PolicyLevel.RESTRICTED

    def test_determine_compliance_level_privileged(self):
        violations = [
            Violation(
                "PG-PSS-001", Severity.CRITICAL, Category.POD_SECURITY,
                "Privileged", "Deploy", "a", policy_level=PolicyLevel.BASELINE,
            ),
        ]
        report = AuditReport(scan_path="/tmp", violations=violations)
        report.determine_compliance_level()
        assert report.compliant_level == PolicyLevel.PRIVILEGED
