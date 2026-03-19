"""YAML parser — reads Kubernetes manifests into Resource objects."""
import os
from typing import List

import yaml

from policy_guard.models import Resource


WORKLOAD_KINDS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "Job", "CronJob", "Service", "Ingress", "NetworkPolicy",
    "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
    "ServiceAccount", "ConfigMap", "Secret", "PersistentVolumeClaim",
    "HorizontalPodAutoscaler", "PodDisruptionBudget",
    "LimitRange", "ResourceQuota", "Namespace",
}


def parse_manifests(path: str) -> List[Resource]:
    """Parse all YAML files from a path and return Resource objects."""
    yaml_files = _collect_yaml_files(path)
    resources = []

    for fpath in yaml_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if not kind:
                continue

            metadata = doc.get("metadata", {}) or {}
            spec = doc.get("spec", {}) or {}

            res = Resource(
                kind=kind,
                name=metadata.get("name", "unnamed"),
                namespace=metadata.get("namespace", "default"),
                api_version=doc.get("apiVersion", ""),
                labels=metadata.get("labels", {}) or {},
                annotations=metadata.get("annotations", {}) or {},
                spec=spec,
                raw=doc,
                file_path=fpath,
            )
            resources.append(res)

    return resources


def _collect_yaml_files(path: str) -> list:
    path = os.path.abspath(path)
    if os.path.isfile(path):
        return [path]

    yaml_files = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith((".yaml", ".yml")) and not f.startswith("."):
                yaml_files.append(os.path.join(root, f))
    return sorted(yaml_files)


def get_pod_spec(resource: Resource) -> dict:
    """Extract the pod spec from any workload resource."""
    kind = resource.kind
    spec = resource.spec

    if kind == "Pod":
        return spec

    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        template = spec.get("template", {}) or {}
        return template.get("spec", {}) or {}

    if kind == "CronJob":
        job_template = spec.get("jobTemplate", {}) or {}
        job_spec = job_template.get("spec", {}) or {}
        template = job_spec.get("template", {}) or {}
        return template.get("spec", {}) or {}

    return {}


def get_containers(resource: Resource, include_init: bool = True) -> list:
    """Get all containers from a workload resource."""
    pod_spec = get_pod_spec(resource)
    containers = list(pod_spec.get("containers", []) or [])
    if include_init:
        containers.extend(pod_spec.get("initContainers", []) or [])
    return containers
