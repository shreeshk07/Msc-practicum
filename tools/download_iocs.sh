#!/usr/bin/env bash
# Download fresh IOC lists into data/iocs/ for use by URL-007.
#
# URLhaus is a free abuse.ch service that publishes known malicious
# URLs in plain text, one per line, updated continuously.
#
# PhishTank also offers a public list but needs an API key for bulk
# download. Its URL is noted below for an operator who has a key.
#
# Usage:
#   bash tools/download_iocs.sh
#
# Run periodically (e.g. via cron once an hour). The configured rule
# URL-007 reads from data/iocs/urlhaus_recent.txt automatically.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IOC_DIR="$ROOT/data/iocs"
mkdir -p "$IOC_DIR"

# URLhaus plain-text list (no API key required).
echo "==> URLhaus"
URLHAUS_URL="https://urlhaus.abuse.ch/downloads/text/"
TMP="$IOC_DIR/urlhaus_recent.txt.tmp"
if curl -sL --fail --max-time 60 -o "$TMP" "$URLHAUS_URL"; then
  # Drop comment lines and empties so the IOC matcher only sees data.
  grep -v '^#' "$TMP" | grep -v '^[[:space:]]*$' > "$IOC_DIR/urlhaus_recent.txt"
  rm -f "$TMP"
  n=$(wc -l < "$IOC_DIR/urlhaus_recent.txt")
  echo "  $n indicators saved to data/iocs/urlhaus_recent.txt"
else
  echo "  [warn] URLhaus download failed; existing list (if any) is unchanged"
  rm -f "$TMP"
fi

# PhishTank requires an API key per their TOS. Uncomment and set the
# key to enable.
# PHISHTANK_KEY="${PHISHTANK_KEY:-}"
# if [[ -n "$PHISHTANK_KEY" ]]; then
#   echo "==> PhishTank"
#   curl -sL --fail \
#     "http://data.phishtank.com/data/${PHISHTANK_KEY}/online-valid.csv" \
#     | awk -F',' 'NR>1 { gsub(/"/, "", $2); print $2 }' \
#     > "$IOC_DIR/phishtank_recent.txt"
# fi

echo "Done."
