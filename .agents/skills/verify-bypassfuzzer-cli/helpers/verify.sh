#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
ACTION=${1:-}
RUN_ID=${2:-}

case "$RUN_ID" in
  ''|*[!A-Za-z0-9._-]*) echo "run-id must contain only letters, numbers, dots, underscores, or hyphens" >&2; exit 2 ;;
esac

EVIDENCE="$ROOT/artifacts/verification/bypassfuzzer-cli/$RUN_ID"
JAR="$ROOT/cli/build/libs/bypassfuzzer-cli.jar"

manifest_value() {
  unzip -p "$JAR" META-INF/MANIFEST.MF | tr -d '\r' | sed -n "s/^$1: //p" | head -n 1
}

doctor() {
  test -f "$JAR"
  command -v java >/dev/null
  command -v python3 >/dev/null
  command -v unzip >/dev/null
  test "$(manifest_value Main-Class)" = "com.bypassfuzzer.cli.BypassFuzzerCli"
  test "$(manifest_value Implementation-Title)" = "BypassFuzzer CLI"
  unzip -l "$JAR" payloads/sweep_probes.txt payloads/url_validation_source_data.json | grep -q sweep_probes.txt
  java -jar "$JAR" --help | grep -q 'url-validation'
  for feature in sweep bypass idor url-validation; do
    java -jar "$JAR" "$feature" --help | grep -q -- '--output'
  done
  printf 'doctor=PASS\njar=%s\nversion=%s\n' "$JAR" "$(manifest_value Implementation-Version)"
}

case "$ACTION" in
  launch)
    mkdir -p "$EVIDENCE"
    (cd "$ROOT" && ./gradlew :cli:shadowJar --no-daemon) >"$EVIDENCE/launch.log" 2>&1
    doctor >"$EVIDENCE/doctor.txt"
    sha256sum "$JAR" >"$EVIDENCE/jar.sha256"
    git -C "$ROOT" rev-parse HEAD >"$EVIDENCE/git-revision.txt"
    printf 'launch=PASS\nevidence=%s\n' "$EVIDENCE"
    ;;
  doctor)
    mkdir -p "$EVIDENCE"
    doctor | tee "$EVIDENCE/doctor.txt"
    ;;
  drive)
    FEATURE=${3:-}
    case "$FEATURE" in sweep|bypass|idor|url-validation) ;; *) echo "unknown feature: $FEATURE" >&2; exit 2 ;; esac
    mkdir -p "$EVIDENCE/$FEATURE"
    python3 "$ROOT/.agents/skills/verify-bypassfuzzer-cli/helpers/live_drive.py" \
      "$JAR" "$EVIDENCE/$FEATURE" "$FEATURE" >"$EVIDENCE/$FEATURE/drive.log" 2>&1
    printf 'drive=PASS\nfeature=%s\nevidence=%s\n' "$FEATURE" "$EVIDENCE/$FEATURE"
    ;;
  cleanup)
    if test -f "$EVIDENCE/.scratch/pid"; then
      PID=$(sed -n '1p' "$EVIDENCE/.scratch/pid")
      case "$PID" in ''|*[!0-9]*) ;; *) kill "$PID" 2>/dev/null || true ;; esac
    fi
    if test -d "$EVIDENCE/.scratch"; then rm -rf -- "$EVIDENCE/.scratch"; fi
    printf 'cleanup complete; evidence retained: %s\n' "$EVIDENCE"
    ;;
  *)
    echo "usage: verify.sh <launch|doctor|drive|cleanup> <run-id> [feature]" >&2
    exit 2
    ;;
esac
