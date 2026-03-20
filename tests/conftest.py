"""Shared test fixtures for policy-guard."""
import pytest


@pytest.fixture
def tmp_manifests(tmp_path):
    """Factory fixture: creates temp directory with YAML manifests."""
    def _make(yamls: dict):
        manifest_dir = tmp_path / "manifests"
        manifest_dir.mkdir(exist_ok=True)
        for name, content in yamls.items():
            (manifest_dir / name).write_text(content, encoding="utf-8")
        return str(manifest_dir)
    return _make


@pytest.fixture
def secure_deployment():
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: secure-app\n"
        "  namespace: default\n"
        "spec:\n"
        "  replicas: 2\n"
        "  strategy:\n"
        "    type: RollingUpdate\n"
        "  template:\n"
        "    spec:\n"
        "      automountServiceAccountToken: false\n"
        "      securityContext:\n"
        "        runAsNonRoot: true\n"
        "        seccompProfile:\n"
        "          type: RuntimeDefault\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: myregistry/app:1.2.3\n"
        "          securityContext:\n"
        "            allowPrivilegeEscalation: false\n"
        "            readOnlyRootFilesystem: true\n"
        "            capabilities:\n"
        "              drop: [ALL]\n"
        "            runAsNonRoot: true\n"
        "          resources:\n"
        "            limits:\n"
        "              cpu: 500m\n"
        "              memory: 256Mi\n"
        "            requests:\n"
        "              cpu: 100m\n"
        "              memory: 128Mi\n"
        "          livenessProbe:\n"
        "            httpGet:\n"
        "              path: /healthz\n"
        "              port: 8080\n"
        "          readinessProbe:\n"
        "            httpGet:\n"
        "              path: /ready\n"
        "              port: 8080\n"
    )


@pytest.fixture
def insecure_deployment():
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: insecure-app\n"
        "  namespace: default\n"
        "spec:\n"
        "  replicas: 1\n"
        "  template:\n"
        "    spec:\n"
        "      hostPID: true\n"
        "      hostNetwork: true\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: myapp:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsUser: 0\n"
        "          env:\n"
        "            - name: DB_PASSWORD\n"
        "              value: secret123\n"
        "          volumeMounts:\n"
        "            - name: host\n"
        "              mountPath: /host\n"
        "      volumes:\n"
        "        - name: host\n"
        "          hostPath:\n"
        "            path: /\n"
    )


@pytest.fixture
def dangerous_rbac():
    return (
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n"
        "  name: super-admin\n"
        "rules:\n"
        "  - apiGroups: ['*']\n"
        "    resources: ['*']\n"
        "    verbs: ['*']\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: super-admin-binding\n"
        "roleRef:\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "  kind: ClusterRole\n"
        "  name: cluster-admin\n"
        "subjects:\n"
        "  - kind: ServiceAccount\n"
        "    name: default\n"
        "    namespace: default\n"
    )


@pytest.fixture
def good_manifests(tmp_manifests, secure_deployment):
    return tmp_manifests({"secure.yaml": secure_deployment})


@pytest.fixture
def bad_manifests(tmp_manifests, insecure_deployment, dangerous_rbac):
    return tmp_manifests({
        "insecure.yaml": insecure_deployment,
        "rbac.yaml": dangerous_rbac,
    })
