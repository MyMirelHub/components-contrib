#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PUBSUB_FILE="$ROOT_DIR/components/pubsub.yaml"
RES_FILE="$ROOT_DIR/components/resiliency.yaml"
RES_TIMEOUT_FILE="$ROOT_DIR/components/resiliency-timeout-only.yaml"
RES_RETRY40_FILE="$ROOT_DIR/components/resiliency-retry40.yaml"
OUT_FILE="$ROOT_DIR/results-1175.tsv"

MESSAGES="${MESSAGES:-240}"
WAIT_HEALTH_SECS="${WAIT_HEALTH_SECS:-120}"
POST_SLEEP_SECS="${POST_SLEEP_SECS:-35}"
APP_CONCURRENCY_SET="${APP_CONCURRENCY_SET:-1}"
HANDLERS_SET="${HANDLERS_SET:-1}"

cp "$PUBSUB_FILE" /tmp/pulsar-pubsub.yaml.bak
cp "$RES_FILE" /tmp/pulsar-resiliency.yaml.bak

cleanup() {
  cp /tmp/pulsar-pubsub.yaml.bak "$PUBSUB_FILE" >/dev/null 2>&1 || true
  cp /tmp/pulsar-resiliency.yaml.bak "$RES_FILE" >/dev/null 2>&1 || true
  docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf "mode\tapp_strategy\tresiliency\tmax_concurrent_handlers\tapp_concurrency\tretriable_from_app\tasync_processing_errors\trecovered_21\trecovered_any\tapp_busy_429\n" > "$OUT_FILE"

set_max_handlers() {
  local handlers="$1"
  perl -0777 -i -pe "s/(- name: maxConcurrentHandlers\\n\\s*value: )\"[^\"]+\"/\$1\"$handlers\"/g" "$PUBSUB_FILE"
}

count_match() {
  local haystack="$1"
  local pattern="$2"
  if [[ -z "$haystack" ]]; then
    echo "0"
  else
    printf '%s' "$haystack" | rg -c "$pattern" 2>/dev/null || echo "0"
  fi
}

set_process_mode() {
  local mode="$1"
  perl -0777 -i -pe "s/(- name: processMode\\n\\s*value: )\"[^\"]+\"/\$1\"$mode\"/g" "$PUBSUB_FILE"
}

for mode in async sync; do
  set_process_mode "$mode"

  for strategy in immediate429 internalRetry; do
    for profile in timeout-only retry40; do
      if [[ "$profile" == "timeout-only" ]]; then
        cp "$RES_TIMEOUT_FILE" "$RES_FILE"
      else
        cp "$RES_RETRY40_FILE" "$RES_FILE"
      fi

      for app_c in $APP_CONCURRENCY_SET; do
        for handlers in $HANDLERS_SET; do
        set_max_handlers "$handlers"
        echo "=== mode=$mode strategy=$strategy profile=$profile handlers=$handlers app_c=$app_c ==="

        docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true

        APP_MAX_CONCURRENCY="$app_c" \
        APP_BUSY_STRATEGY="$strategy" \
        APP_INTERNAL_MAX_RETRIES="20" \
        APP_INTERNAL_RETRY_DELAY="200ms" \
        APP_SLEEP_AFTER_EXHAUST="false" \
        docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" up --build -d --scale loadgen=0 >/dev/null

        for ((j=1; j<=WAIT_HEALTH_SECS; j++)); do
          if curl -sf http://localhost:3501/v1.0/healthz >/dev/null 2>&1; then
            break
          fi
          sleep 1
        done

        for ((i=1; i<=MESSAGES; i++)); do
          curl -s -o /dev/null -X POST http://localhost:3501/v1.0/publish/messagebus/storm-topic \
            -H 'Content-Type: application/json' \
            -d "{\"id\":$i,\"payload\":\"x\"}" || true
        done

        sleep "$POST_SLEEP_SECS"

        DLOG="$(docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" logs --no-color daprd 2>/dev/null || true)"
        ALOG="$(docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml" logs --no-color app 2>/dev/null || true)"

        RETRIES="$(count_match "$DLOG" 'retriable error returned from app')"
        ASYNCERR="$(count_match "$DLOG" 'Error async processing message')"
        RECOV21="$(count_match "$DLOG" 'Recovered processing operation.*after 21 attempts')"
        RECOVANY="$(count_match "$DLOG" 'Recovered processing operation')"
        BUSY="$(count_match "$ALOG" 'app busy: returning 429')"

        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
          "$mode" "$strategy" "$profile" "$handlers" "$app_c" \
          "$RETRIES" "$ASYNCERR" "$RECOV21" "$RECOVANY" "$BUSY" >> "$OUT_FILE"

        echo "RESULT mode=$mode strategy=$strategy profile=$profile handlers=$handlers app_c=$app_c retriable=$RETRIES asyncErr=$ASYNCERR recov21=$RECOV21 recovAny=$RECOVANY busy429=$BUSY"
        done
      done
    done
  done
done

echo "Wrote matrix results to $OUT_FILE"
