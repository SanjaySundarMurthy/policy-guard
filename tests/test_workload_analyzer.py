"""Tests for policy-guard workload analyzer."""
from policy_guard.parser import parse_manifests
from policy_guard.analyzers.workload_analyzer import analyze


class TestWorkloadAnalyzer:
    def test_single_replica_detected(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-WRK-001" in rule_ids  # single replica

    def test_secure_deployment_fewer_issues(self, good_manifests):
        resources = parse_manifests(good_manifests)
        violations = analyze(resources)
        # secure deployment has replicas: 2, so should not trigger PG-WRK-001
        assert "PG-WRK-001" not in [v.rule_id for v in violations]

    def test_empty_resources(self):
        violations = analyze([])
        assert violations == []
