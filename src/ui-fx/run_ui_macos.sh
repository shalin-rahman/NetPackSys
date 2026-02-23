#!/usr/bin/env bash
# NetPackSys UI — quick run on macOS (Apple Silicon and Intel)
# Usage: ./run_ui_macos.sh [--live]
#   --live  run with sudo so live packet capture works (optional)
# Requires: JDK 21+, Maven, libpcap (brew install libpcap)

set -e
LIVE=""
for arg in "$@"; do
  if [ "$arg" = "--live" ]; then LIVE=1; fi
done

# Java 17+ needs this for JNA native access (live capture)
export MAVEN_OPTS="${MAVEN_OPTS:-} --enable-native-access=ALL-UNNAMED"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building NetPackSys core..."
(cd "$ROOT" && mvn clean install -DskipTests -q)

echo "Starting Packet Log Viewer..."
cd "$SCRIPT_DIR"
if [ -n "$LIVE" ]; then
  echo "Running with elevated privileges for live capture (you may be prompted for password)."
  exec sudo mvn clean javafx:run
else
  exec mvn clean javafx:run
fi
