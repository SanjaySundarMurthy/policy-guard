FROM python:3.12-slim AS builder

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir build && python -m build

FROM python:3.12-slim

LABEL maintainer="ssan" \
      org.opencontainers.image.source="https://github.com/SanjaySundarMurthy/policy-guard" \
      org.opencontainers.image.description="k8s-policy-guard - DevOps CLI Tool"

RUN groupadd -r appuser && useradd -r -g appuser appuser
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER appuser
ENTRYPOINT ["policy-guard"]
CMD ["--help"]
