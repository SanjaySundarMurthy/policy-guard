"""Tests for policy-guard container security analyzer."""
from policy_guard.parser import parse_manifests
from policy_guard.analyzers.container_security import analyze


class TestContainerSecurityAnalyzer:
    def test_secure_deployment_minimal_violations(self, good_manifests):
        resources = parse_manifests(good_manifests)
        violations = analyze(resources)
        # Secure deployment has pinned tags, probes, resources
        img_ctr_ids = [v.rule_id for v in violations if v.rule_id.startswith(("PG-IMG", "PG-CTR"))]
        # May have PG-IMG-002 (not pinned to digest) but should be few
        assert len(img_ctr_ids) <= 3

    def test_insecure_detects_latest_tag(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-IMG-001" in rule_ids  # latest tag

    def test_insecure_missing_probes(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        # insecure deployment has no probes
        assert "PG-CTR-001" in rule_ids or "PG-CTR-002" in rule_ids

    def test_insecure_no_resources(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-CTR-003" in rule_ids  # no resource limits

    def test_insecure_secrets_in_env(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        violations = analyze(resources)
        rule_ids = [v.rule_id for v in violations]
        assert "PG-CTR-007" in rule_ids  # secrets in env vars

    def test_no_resources(self):
        violations = analyze([])
        assert violations == []
