"""Demo mode — creates realistic K8s manifests with security issues."""
import os
import tempfile


def create_demo_manifests() -> str:
    demo_dir = tempfile.mkdtemp(prefix="policy-guard-demo-")

    # 1. Privileged deployment with tons of issues
    _write(demo_dir, "01-insecure-deployment.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payment-service
  template:
    metadata:
      labels:
        app: payment-service
    spec:
      containers:
      - name: payment
        image: company-registry.io/payments:latest
        ports:
        - containerPort: 8080
          hostPort: 8080
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
        env:
        - name: DB_PASSWORD
          value: "super-secret-p4ssw0rd!"
        - name: API_KEY
          value: "sk_live_abc123xyz"
        volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
      hostPID: true
      hostNetwork: true
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
""")

    # 2. A slightly better but still flawed deployment
    _write(demo_dir, "02-backend-api.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-api
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: backend-api
  template:
    metadata:
      labels:
        app: backend-api
    spec:
      containers:
      - name: api
        image: nginx
        ports:
        - containerPort: 8080
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
        resources:
          requests:
            memory: 128Mi
            cpu: 100m
      - name: sidecar
        image: envoyproxy/envoy:latest
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
            - SYS_PTRACE
""")

    # 3. Well-hardened deployment (should pass most checks)
    _write(demo_dir, "03-hardened-frontend.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: frontend
    spec:
      automountServiceAccountToken: false
      serviceAccountName: frontend-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: frontend
        image: gcr.io/myproject/frontend:v2.1.3
        ports:
        - containerPort: 3000
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            memory: 128Mi
            cpu: 100m
          limits:
            memory: 256Mi
            cpu: 500m
        livenessProbe:
          httpGet:
            path: /healthz
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 15
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
""")

    # 4. Overprivileged RBAC
    _write(demo_dir, "04-rbac.yaml", """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dev-team-admin
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-manager
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update", "delete"]
- apiGroups: [""]
  resources: ["pods/exec", "pods/attach"]
  verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default-secret-access
  namespace: production
subjects:
- kind: ServiceAccount
  name: default
  namespace: production
roleRef:
  kind: Role
  name: secret-manager
  apiGroup: rbac.authorization.k8s.io
""")

    # 5. Network exposure
    _write(demo_dir, "05-services.yaml", """apiVersion: v1
kind: Service
metadata:
  name: payment-external
  namespace: production
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8080
  selector:
    app: payment-service
---
apiVersion: v1
kind: Service
metadata:
  name: debug-nodeport
  namespace: production
spec:
  type: NodePort
  ports:
  - port: 8080
    nodePort: 30080
  selector:
    app: backend-api
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      location /debug { proxy_pass http://localhost:6060; }
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: backend-api
            port:
              number: 8080
""")

    # 6. CronJob with issues
    _write(demo_dir, "06-cronjob.yaml", """apiVersion: batch/v1
kind: CronJob
metadata:
  name: db-backup
  namespace: production
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:latest
            command: ["pg_dump"]
            env:
            - name: PGPASSWORD
              value: "backup-password-123"
          restartPolicy: OnFailure
""")

    return demo_dir


def _write(directory: str, filename: str, content: str):
    with open(os.path.join(directory, filename), "w", encoding="utf-8") as f:
        f.write(content.lstrip("\n"))
