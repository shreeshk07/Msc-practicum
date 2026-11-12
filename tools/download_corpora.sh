#!/usr/bin/env bash
# Download and extract the public corpora used by PhishTriage experiments.
# Idempotent: re-running will not re-download files already present.
#
# Usage:
#   bash tools/download_corpora.sh
#
# Output layout:
#   data/raw/spamassassin/easy_ham/          2500 legitimate messages
#   data/raw/spamassassin/hard_ham/           250 legitimate messages
#   data/raw/spamassassin/spam/                500 spam/phishing messages
#   data/raw/spamassassin/spam_2/             1400 spam/phishing messages (newer)
#   data/raw/nazario/phishing-2024.mbox      ~15 MB of phishing emails
#   data/raw/nazario/phishing-2025.mbox      ~18 MB of phishing emails

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SA_DIR="$ROOT/data/raw/spamassassin"
NZ_DIR="$ROOT/data/raw/nazario"

mkdir -p "$SA_DIR" "$NZ_DIR"

SA_BASE="https://spamassassin.apache.org/old/publiccorpus"
SA_FILES=(
  "20021010_spam.tar.bz2"        # 'spam'
  "20030228_easy_ham.tar.bz2"    # 'easy_ham'
  "20030228_hard_ham.tar.bz2"    # 'hard_ham'
  "20050311_spam_2.tar.bz2"      # 'spam_2' (newer)
)

echo "==> SpamAssassin corpus"
cd "$SA_DIR"
for f in "${SA_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    echo "  [skip] $f already downloaded"
  else
    echo "  [get]  $f"
    curl -sL --fail --max-time 120 -o "$f" "$SA_BASE/$f"
  fi
  # Extract only if the corresponding directory does not exist yet.
  expected_dir="$(echo "$f" | sed -E 's/^[0-9]+_(.*)\.tar\.bz2$/\1/')"
  if [[ -d "$expected_dir" ]]; then
    echo "  [skip] $expected_dir/ already extracted"
  else
    echo "  [tar]  $f"
    tar -xjf "$f"
  fi
done

NZ_BASE="https://monkey.org/~jose/phishing"
NZ_YEARS=(2023 2024 2025)

echo "==> Nazario phishing corpora"
cd "$NZ_DIR"
for y in "${NZ_YEARS[@]}"; do
  out="phishing-${y}.mbox"
  if [[ -f "$out" ]]; then
    echo "  [skip] $out already downloaded"
  else
    echo "  [get]  $out"
    curl -sL --fail --max-time 180 -o "$out" "$NZ_BASE/phishing-${y}"
  fi
done

echo ""
echo "Done. Quick counts:"
for d in easy_ham hard_ham spam spam_2; do
  if [[ -d "$SA_DIR/$d" ]]; then
    n=$(find "$SA_DIR/$d" -type f | wc -l)
    printf "  spamassassin/%-10s %5d messages\n" "$d" "$n"
  fi
done
for f in "$NZ_DIR"/phishing-*.mbox; do
  if [[ -f "$f" ]]; then
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f")
    printf "  %s  %s bytes\n" "$(basename "$f")" "$sz"
  fi
done
