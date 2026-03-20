"""Tests for policy-guard YAML parser."""
from policy_guard.parser import parse_manifests, get_pod_spec, get_containers
from policy_guard.models import Resource


class TestParseManifests:
    def test_parse_deployment(self, tmp_manifests, secure_deployment):
        path = tmp_manifests({"deploy.yaml": secure_deployment})
        resources = parse_manifests(path)
        assert len(resources) == 1
        assert resources[0].kind == "Deployment"
        assert resources[0].name == "secure-app"

    def test_parse_multiple(self, bad_manifests):
        resources = parse_manifests(bad_manifests)
        assert len(resources) >= 2  # insecure deployment + rbac resources

    def test_parse_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        resources = parse_manifests(str(empty))
        assert resources == []

    def test_parse_invalid_yaml(self, tmp_manifests):
        path = tmp_manifests({"bad.yaml": "{{not valid yaml{{"})
        resources = parse_manifests(path)
        assert resources == []

    def test_parse_single_file(self, tmp_path, secure_deployment):
        f = tmp_path / "deploy.yaml"
        f.write_text(secure_deployment, encoding="utf-8")
        resources = parse_manifests(str(f))
        assert len(resources) == 1

    def test_parse_multi_document(self, tmp_manifests, dangerous_rbac):
        path = tmp_manifests({"rbac.yaml": dangerous_rbac})
        resources = parse_manifests(path)
        kinds = [r.kind for r in resources]
        assert "ClusterRole" in kinds
        assert "ClusterRoleBinding" in kinds


class TestGetPodSpec:
    def test_deployment_pod_spec(self):
        res = Resource(
            kind="Deployment",
            name="test",
            spec={"template": {"spec": {"containers": [{"name": "app"}]}}},
        )
        pod_spec = get_pod_spec(res)
        assert "containers" in pod_spec

    def test_pod_spec(self):
        res = Resource(kind="Pod", name="test", spec={"containers": [{"name": "app"}]})
        pod_spec = get_pod_spec(res)
        assert "containers" in pod_spec

    def test_service_returns_empty(self):
        res = Resource(kind="Service", name="test", spec={"ports": [{"port": 80}]})
        pod_spec = get_pod_spec(res)
        assert pod_spec == {}


class TestGetContainers:
    def test_get_containers_from_deployment(self):
        res = Resource(
            kind="Deployment",
            name="test",
            spec={
                "template": {"spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "initContainers": [{"name": "init", "image": "busybox"}],
                }}
            },
        )
        containers = get_containers(res)
        assert len(containers) == 2

    def test_get_containers_no_init(self):
        res = Resource(
            kind="Deployment",
            name="test",
            spec={
                "template": {"spec": {
                    "containers": [{"name": "app"}],
                    "initContainers": [{"name": "init"}],
                }}
            },
        )
        containers = get_containers(res, include_init=False)
        assert len(containers) == 1
        assert containers[0]["name"] == "app"
