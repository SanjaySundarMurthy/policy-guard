"""Tests for policy-guard pod security analyzer."""
from policy_guard.parser import parse_manifests
from policy_guard.analyzers.pod_security import analyze


class TestPodSecurityAnalyzer:
    def test_secure_deployment_minimal_violations(self, good_manifests):
        resources = parse_manifests(good_manifests)
        violations = analyze(resources)
        pss_ids = [v.rule_id for v in violations if v.rule_id.startswith("PG-PSS")]
        # Secure deployment should have very few PSS violations
        assert len(pss_ids) <= 2

    def test_insecure_detects_privileged(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-PSS-001" in rule_ids  # privileged container

    def test_insecure_detects_host_pid(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-PSS-002" in rule_ids  # hostPID

    def test_insecure_detects_host_network(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-PSS-004" in rule_ids  # hostNetwork

    def test_insecure_detects_hostpath(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-PSS-005" in rule_ids  # hostPath

    def test_insecure_detects_run_as_root(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-PSS-010" in rule_ids  # runAsUser: 0

    def test_no_resources(self):
        violations = analyze([])
        assert violations == []
