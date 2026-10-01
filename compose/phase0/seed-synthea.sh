#!/usr/bin/env bash
# Seed HAPI FHIR with ~50 Synthea synthetic patients.
#
# Downloads a pinned synthea-with-dependencies.jar (cached in .synthea/,
# gitignored) and runs it in a JRE container — no host Java needed.
#
# NOTE: re-running duplicates patients (transaction bundles POST new
# resources). To reset: docker compose down -v, bring back up, re-seed.
set -euo pipefail
cd "$(dirname "$0")"

FHIR_BASE="${FHIR_BASE:-http://localhost:8081/fhir}"
PATIENT_COUNT="${PATIENT_COUNT:-50}"
SYNTHEA_VERSION="v4.0.0"
SYNTHEA_DIR="$PWD/.synthea"
# Versioned cache name, so bumping SYNTHEA_VERSION never reuses an old jar.
JAR="$SYNTHEA_DIR/synthea-${SYNTHEA_VERSION}-with-dependencies.jar"
JAR_URL="https://github.com/synthetichealth/synthea/releases/download/${SYNTHEA_VERSION}/synthea-with-dependencies.jar"

mkdir -p "$SYNTHEA_DIR"

if [ ! -f "$JAR" ]; then
  echo "==> Downloading Synthea ${SYNTHEA_VERSION}..."
  curl -fL --progress-bar -o "$JAR" "$JAR_URL"
fi

rm -rf "$SYNTHEA_DIR/output"

echo "==> Generating ${PATIENT_COUNT} synthetic patients (FHIR R4 transaction bundles)..."
docker run --rm -v "$SYNTHEA_DIR:/synthea" -w /synthea eclipse-temurin:25-jre \
  java -jar "$(basename "$JAR")" \
  -p "$PATIENT_COUNT" \
  --exporter.fhir.transaction_bundle=true \
  --exporter.baseDirectory /synthea/output

echo "==> Waiting for HAPI FHIR at ${FHIR_BASE}..."
for i in $(seq 1 60); do
  curl -sf "${FHIR_BASE}/metadata" -o /dev/null && break
  [ "$i" -eq 60 ] && { echo "HAPI not ready after 5 minutes" >&2; exit 1; }
  sleep 5
done

post_bundle() {
  local file="$1"
  curl -sf -X POST "$FHIR_BASE" \
    -H 'Content-Type: application/fhir+json' \
    --data-binary "@${file}" -o /dev/null \
    || { echo "FAILED: $(basename "$file")" >&2; return 1; }
  echo "   posted $(basename "$file")"
}

OUT="$SYNTHEA_DIR/output/fhir"

echo "==> Posting organization/practitioner bundles first (reference targets)..."
for f in "$OUT"/hospitalInformation*.json "$OUT"/practitionerInformation*.json; do
  [ -e "$f" ] && post_bundle "$f"
done

echo "==> Posting patient bundles..."
count=0
for f in "$OUT"/*.json; do
  case "$(basename "$f")" in
    hospitalInformation*|practitionerInformation*) continue ;;
  esac
  post_bundle "$f"
  count=$((count + 1))
done

echo "==> Done: ${count} patient bundles loaded into ${FHIR_BASE}"
