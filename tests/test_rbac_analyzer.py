"""Tests for policy-guard RBAC analyzer."""
from policy_guard.parser import parse_manifests
from policy_guard.analyzers.rbac_analyzer import analyze


class TestRbacAnalyzer:
    def test_dangerous_rbac_detects_wildcard_resources(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-RBAC-001" in rule_ids  # wildcard resources

    def test_dangerous_rbac_detects_wildcard_verbs(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-RBAC-002" in rule_ids  # wildcard verbs

    def test_dangerous_rbac_detects_clusteradmin_binding(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-RBAC-010" in rule_ids  # cluster-admin binding

    def test_dangerous_rbac_detects_default_sa_binding(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-RBAC-009" in rule_ids  # default SA binding

    def test_no_rbac_resources(self, good_manifests):
        resources = parse_manifests(good_manifests)
        violations = analyze(resources)
        rbac_ids = [v.rule_id for v in violations if v.rule_id.startswith("PG-RBAC")]
        assert rbac_ids == []

    def test_empty_resources(self):
        violations = analyze([])
        assert violations == []
