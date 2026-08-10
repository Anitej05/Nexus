#!/usr/bin/env sh
set -eu

broker='redpanda:9092'
ready_marker='/run/redpanda-bootstrap/ready'

verify_topic() {
  topic="$1"
  config="$(rpk topic describe "$topic" -X "brokers=$broker" --print-configs)"
  printf '%s\n' "$config" | grep -Eq '(cleanup.policy|CLEANUP_POLICY).*compact,delete'
  printf '%s\n' "$config" | grep -Eq '(retention.ms|RETENTION_MS).*604800000'
  printf '%s\n' "$config" | grep -Eq '(segment.ms|SEGMENT_MS).*86400000'
}

verify_topics() {
  for topic in \
    nexus.raw.v1 \
    nexus.observations.v1 \
    nexus.features.v1 \
    nexus.predictions.v1 \
    nexus.signals.v1 \
    nexus.dead-letter.v1 \
    nexus.ontology.projection.v1 \
    nexus.audit.v1; do
    verify_topic "$topic"
  done
}

if [ "${1:-}" = '--healthcheck' ]; then
  test -f "$ready_marker"
  verify_topics
  exit 0
fi

# Canonical envelope Kafka keys are always tenant_id:subject.
rm -f "$ready_marker"
for topic in \
  nexus.raw.v1 \
  nexus.observations.v1 \
  nexus.features.v1 \
  nexus.predictions.v1 \
  nexus.signals.v1 \
  nexus.dead-letter.v1 \
  nexus.ontology.projection.v1 \
  nexus.audit.v1; do
  if ! rpk topic describe "$topic" -X "brokers=$broker" >/dev/null 2>&1; then
    rpk topic create "$topic" -X "brokers=$broker" --partitions 3 --replicas 1
  fi
  rpk topic alter-config "$topic" -X "brokers=$broker" \
    --set cleanup.policy=compact,delete \
    --set retention.ms=604800000 \
    --set segment.ms=86400000
done

verify_topics
touch "$ready_marker"

# Keep Compose's --wait target resident; failure above deliberately restarts it.
while :; do sleep 3600; done
