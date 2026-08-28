#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ACTIVE_PGID=""

usage() {
  echo "usage: $0 launch <run-id> | doctor <run-id> | drive <run-id> <feature> | cleanup <run-id>" >&2
  exit 2
}

validate_run_id() {
  local run_id="$1"
  if [[ ! "$run_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "run-id may contain only letters, numbers, dots, underscores, and hyphens" >&2
    exit 2
  fi
}

cleanup_active_group() {
  if [[ -n "$ACTIVE_PGID" ]] && kill -0 "$ACTIVE_PGID" 2>/dev/null; then
    kill -TERM -- "-$ACTIVE_PGID" 2>/dev/null || true
    for _attempt in {1..20}; do
      if ! kill -0 "$ACTIVE_PGID" 2>/dev/null; then
        ACTIVE_PGID=""
        return
      fi
      sleep 0.1
    done
    kill -KILL -- "-$ACTIVE_PGID" 2>/dev/null || true
  fi
  ACTIVE_PGID=""
}

trap cleanup_active_group EXIT INT TERM

run_logged() {
  local log_file="$1"
  shift
  mkdir -p "$(dirname "$log_file")"
  setsid "$@" >"$log_file" 2>&1 &
  ACTIVE_PGID=$!
  local status=0
  wait "$ACTIVE_PGID" || status=$?
  ACTIVE_PGID=""
  sed -n '1,240p' "$log_file"
  if (( status != 0 )); then
    echo "command failed with exit code $status; full transcript: $log_file" >&2
    return "$status"
  fi
}

manifest_value() {
  local jar_file="$1"
  local key="$2"
  unzip -p "$jar_file" META-INF/MANIFEST.MF \
    | tr -d '\r' \
    | awk -F': ' -v wanted="$key" '$1 == wanted { print $2; exit }'
}

expected_version() {
  awk -F"'" '/^version = / { print $2; exit }' "$REPO_ROOT/build.gradle"
}

copy_results() {
  local evidence_dir="$1"
  local task="$2"
  local source_dir="$REPO_ROOT/build/test-results/$task"
  if [[ -d "$source_dir" ]]; then
    mkdir -p "$evidence_dir/test-results"
    rm -rf "$evidence_dir/test-results/$task"
    cp -R "$source_dir" "$evidence_dir/test-results/$task"
  fi
}

launch() {
  local run_id="$1"
  local evidence_dir="$REPO_ROOT/artifacts/verification/bypassfuzzer/$run_id"
  mkdir -p "$evidence_dir"
  run_logged "$evidence_dir/launch.log" sh "$REPO_ROOT/build.sh" --no-daemon shadowJar

  local jar_file="$REPO_ROOT/build/libs/bypassfuzzer.jar"
  [[ -f "$jar_file" ]] || { echo "missing $jar_file" >&2; exit 1; }
  {
    echo "repository=$REPO_ROOT"
    echo "revision=$(git -C "$REPO_ROOT" rev-parse HEAD)"
    echo "implementation_title=$(manifest_value "$jar_file" Implementation-Title)"
    echo "implementation_version=$(manifest_value "$jar_file" Implementation-Version)"
    echo "jar_sha256=$(sha256sum "$jar_file" | awk '{print $1}')"
    echo "jar=$jar_file"
  } >"$evidence_dir/launch.txt"
  echo "launch ready: $jar_file"
  echo "evidence: $evidence_dir"
}

doctor() {
  local run_id="$1"
  local evidence_dir="$REPO_ROOT/artifacts/verification/bypassfuzzer/$run_id"
  local jar_file="$REPO_ROOT/build/libs/bypassfuzzer.jar"
  mkdir -p "$evidence_dir"

  [[ -x /usr/bin/burpsuite ]] || { echo "missing /usr/bin/burpsuite" >&2; exit 1; }
  [[ -f "$jar_file" ]] || { echo "missing $jar_file; run launch first" >&2; exit 1; }
  local java_major
  java_major="$(java -version 2>&1 | awk -F'"' '/version/ { split($2, parts, "."); print parts[1]; exit }')"
  [[ "$java_major" =~ ^[0-9]+$ ]] && (( java_major >= 17 )) \
    || { echo "Java 17+ is required; found $java_major" >&2; exit 1; }

  local title version expected
  title="$(manifest_value "$jar_file" Implementation-Title)"
  version="$(manifest_value "$jar_file" Implementation-Version)"
  expected="$(expected_version)"
  [[ "$title" == "BypassFuzzer" ]] || { echo "unexpected manifest title: $title" >&2; exit 1; }
  [[ "$version" == "$expected" ]] || { echo "manifest version $version does not match build.gradle $expected" >&2; exit 1; }

  local entries=(
    "com/bypassfuzzer/burp/BurpExtender.class"
    "com/bypassfuzzer/burp/ui/BypassFuzzerTab.class"
    "payloads/sweep_probes.txt"
    "payloads/url_validation_source_data.json"
    "bypassfuzzer-build.properties"
  )
  local listing
  listing="$(unzip -Z1 "$jar_file")"
  for entry in "${entries[@]}"; do
    grep -Fqx "$entry" <<<"$listing" || { echo "JAR is missing $entry" >&2; exit 1; }
  done

  {
    echo "doctor=PASS"
    echo "java_major=$java_major"
    echo "burp_launcher=/usr/bin/burpsuite"
    echo "implementation_title=$title"
    echo "implementation_version=$version"
    echo "jar_sha256=$(sha256sum "$jar_file" | awk '{print $1}')"
    printf 'checked_entry=%s\n' "${entries[@]}"
  } >"$evidence_dir/doctor.txt"
  sed -n '1,160p' "$evidence_dir/doctor.txt"
  echo "evidence: $evidence_dir"
}

run_gradle() {
  local evidence_dir="$1"
  local log_name="$2"
  shift 2
  run_logged "$evidence_dir/$log_name" "$REPO_ROOT/gradlew" --no-daemon --console=plain --rerun-tasks "$@"
}

drive() {
  local run_id="$1"
  local feature="$2"
  local evidence_dir="$REPO_ROOT/artifacts/verification/bypassfuzzer/$run_id/$feature"
  mkdir -p "$evidence_dir"
  doctor "$run_id" >"$evidence_dir/doctor-before-drive.txt"

  case "$feature" in
    dashboard)
      run_gradle "$evidence_dir" swing-controls.log test \
        --tests com.bypassfuzzer.burp.ui.BypassFuzzerTabTest.startsWithDashboardSweepAndTargetedModeTabs \
        --tests com.bypassfuzzer.burp.ui.BypassFuzzerTabTest.updateBannerShowsVersionDetailsAndCanBeDismissed \
        --tests com.bypassfuzzer.burp.ui.dashboard.DashboardPanelTest
      copy_results "$evidence_dir" test
      ;;
    sweep)
      run_gradle "$evidence_dir" swing-and-engine.log test \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.modeSelectorShowsOnlyTheRelevantSourceControls \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.previewTableUpdatesAfterLoadingProxyHistory \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.importsTargetUrlsFromTextFileIntoPreviewTable \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.probePreviewRendersExactGeneratedRequests \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.payloadSetDefaultsToHighSignalAndCanSelectAllPayloads \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.requestHeadersMenuOffersSyntheticAndBrowserLikeUserAgentRandomization \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.userAgentRandomizationOverridesFixedHeaderAtEngineBoundary \
        --tests com.bypassfuzzer.burp.ui.session.CoverageSweepPanelTest.startAndStopButtonsReflectRunningState \
        --tests com.bypassfuzzer.burp.ui.session.CentralizedExecutionControlsTest \
        --tests com.bypassfuzzer.burp.ui.session.SessionResultsWorkspaceTest.sharedWorkspaceAlwaysExposesTheRetryQueueControl \
        --tests com.bypassfuzzer.burp.ui.session.SwingBatchDispatcherTest \
        --tests com.bypassfuzzer.burp.http.UserAgentRandomizerTest \
        --tests com.bypassfuzzer.burp.core.attacks.AttackResultTest \
        --tests com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest.allPayloadExecutionCompletesTheEntireGeneratedCatalog \
        --tests com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest.configuredConcurrencyIsAnActualUpperBound \
        --tests com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest.plansOnlyCandidatesThatHaveAnAvailableWorker \
        --tests com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest.highSignalPromotesFullCatalogBackslashMutationsAtEverySegment \
        --tests com.bypassfuzzer.burp.core.coverage.CoverageSweepEngineTest.executionLabelsLikelyBypassResults
      copy_results "$evidence_dir" test
      ;;
    bypass)
      run_gradle "$evidence_dir" user-path.log test \
        --tests com.bypassfuzzer.burp.menu.ContextMenuFactoryTest \
        --tests com.bypassfuzzer.burp.ui.BypassFuzzerTabTest.requestSessionIsNestedUnderSelectedMode \
        --tests com.bypassfuzzer.burp.ui.FuzzingSessionTabTest.bypassKeepsAttackTypesInlineAndMovesRunOptionsBehindButton \
        --tests com.bypassfuzzer.burp.ui.session.CentralizedExecutionControlsTest \
        --tests com.bypassfuzzer.burp.ui.session.SessionResultsWorkspaceTest.sharedWorkspaceAlwaysExposesTheRetryQueueControl \
        --tests com.bypassfuzzer.burp.core.attacks.AttackExecutorThrottleTest \
        --tests com.bypassfuzzer.burp.core.FuzzerEngineThrottleTest \
        --tests com.bypassfuzzer.burp.core.throttle.RetryQueueTest
      copy_results "$evidence_dir" test
      run_gradle "$evidence_dir" live-engine.log smokeTestPlaybooks \
        --tests com.bypassfuzzer.burp.smoke.AttackPlaybookSmokeTest.headerAttackFindsHeaderBypass
      copy_results "$evidence_dir" smokeTestPlaybooks
      run_logged "$evidence_dir/live-lab-black-box.log" python3 \
        "$REPO_ROOT/src/test/vulnerable_lab/run_smoke_tests.py"
      ;;
    idor)
      run_gradle "$evidence_dir" swing-and-engine.log test \
        --tests com.bypassfuzzer.burp.menu.ContextMenuFactoryTest \
        --tests com.bypassfuzzer.burp.ui.FuzzingSessionTabTest.idorMovesIdentifiersAndRunOptionsBehindConfigureAttack \
        --tests com.bypassfuzzer.burp.ui.session.IdorRunOptionsPanelTest \
        --tests com.bypassfuzzer.burp.ui.session.CentralizedExecutionControlsTest \
        --tests com.bypassfuzzer.burp.ui.session.SessionResultsWorkspaceTest.sharedWorkspaceAlwaysExposesTheRetryQueueControl \
        --tests com.bypassfuzzer.burp.core.idor.IdorEngineTest \
        --tests com.bypassfuzzer.burp.core.idor.IdorPlaybookBehaviorTest
      copy_results "$evidence_dir" test
      ;;
    url-validation)
      run_gradle "$evidence_dir" user-path.log test \
        --tests com.bypassfuzzer.burp.menu.ContextMenuFactoryTest \
        --tests com.bypassfuzzer.burp.ui.FuzzingSessionTabTest.targetedSessionContainsOnlyItsSelectedMode \
        --tests com.bypassfuzzer.burp.ui.session.UrlValidationOptionsPanelTest \
        --tests com.bypassfuzzer.burp.ui.session.CentralizedExecutionControlsTest \
        --tests com.bypassfuzzer.burp.ui.session.SessionResultsWorkspaceTest.sharedWorkspaceAlwaysExposesTheRetryQueueControl \
        --tests com.bypassfuzzer.burp.core.urlvalidation.UrlValidationCandidateFinderTest \
        --tests com.bypassfuzzer.burp.core.urlvalidation.UrlValidationPayloadGeneratorTest
      copy_results "$evidence_dir" test
      run_gradle "$evidence_dir" live-engine.log smokeTestPlaybooks \
        --tests com.bypassfuzzer.burp.smoke.AttackPlaybookSmokeTest.urlValidationMarkerModeFindsAbsoluteUrlBypass
      copy_results "$evidence_dir" smokeTestPlaybooks
      ;;
    *)
      echo "unknown feature '$feature'; expected dashboard, sweep, bypass, idor, or url-validation" >&2
      exit 2
      ;;
  esac

  {
    echo "drive=PASS"
    echo "feature=$feature"
    echo "run_id=$run_id"
    echo "completed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$evidence_dir/result.txt"
  cat "$evidence_dir/result.txt"
  echo "evidence: $evidence_dir"
}

cleanup() {
  local run_id="$1"
  local evidence_dir="$REPO_ROOT/artifacts/verification/bypassfuzzer/$run_id"
  local scratch_dir="$REPO_ROOT/.agents/skills/verify-bypassfuzzer/.runs/$run_id"
  cleanup_active_group
  if [[ -d "$scratch_dir" ]]; then
    rm -rf "$scratch_dir"
  fi
  [[ -d "$evidence_dir" ]] || { echo "evidence directory is missing: $evidence_dir" >&2; exit 1; }
  echo "cleanup complete; evidence retained: $evidence_dir"
}

[[ $# -ge 2 ]] || usage
command_name="$1"
run_id="$2"
validate_run_id "$run_id"
cd "$REPO_ROOT"

case "$command_name" in
  launch)
    [[ $# -eq 2 ]] || usage
    launch "$run_id"
    ;;
  doctor)
    [[ $# -eq 2 ]] || usage
    doctor "$run_id"
    ;;
  drive)
    [[ $# -eq 3 ]] || usage
    drive "$run_id" "$3"
    ;;
  cleanup)
    [[ $# -eq 2 ]] || usage
    cleanup "$run_id"
    ;;
  *) usage ;;
esac
