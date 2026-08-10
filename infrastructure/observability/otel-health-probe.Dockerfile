FROM python:3.11.9-slim-bookworm@sha256:2856e6af199e8128161abd320575eb9b341f3b76f017b5d0c9cd364f60d8a050
RUN useradd --uid 10001 --create-home probe
COPY infrastructure/observability/otel_health_probe.py /probe.py
USER 10001:10001
ENTRYPOINT ["python", "/probe.py"]
