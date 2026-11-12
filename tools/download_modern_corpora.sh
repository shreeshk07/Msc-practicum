#!/usr/bin/env bash
# Download the modern phishing corpora used by the updated
# experiment protocol.
#
# Sources and licences:
#   Nazario 2023/2024/2025 mbox files
#       https://monkey.org/~jose/phishing/
#       CC-BY 4.0
#   phishing_pot (Pereira / rf-peixoto curated phishing pots)
#       https://github.com/rf-peixoto/phishing_pot
#       CC BY-NC 4.0
#   Champa et al. 2024 "Phishing Email Curated Datasets" (Figshare)
#       https://figshare.com/articles/dataset/Phishing_Email_Curated_Datasets/24899943
#       CC-BY 4.0
#
# Idempotent: re-running does NOT re-download files that already exist.
# The classic SpamAssassin ham baseline is downloaded separately by
# tools/download_corpora.sh and is kept as the legitimate-mail baseline.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NZ_DIR="$ROOT/data/raw/nazario"
PP_DIR="$ROOT/data/raw/phishing_pot"
CH_DIR="$ROOT/data/raw/champa"

mkdir -p "$NZ_DIR" "$PP_DIR" "$CH_DIR"

# Single-shot downloader: fail loud on non-200, cap each attempt at
# 60s, log HTTP code + size, fail the script on empty file.
_get() {
  local url="$1"
  local out="$2"
  if [[ -f "$out" ]] && [[ -s "$out" ]]; then
    local sz
    sz=$(stat -c '%s' "$out" 2>/dev/null || stat -f '%z' "$out")
    printf "  [skip] %-50s (%s bytes already on disk)\n" "$(basename "$out")" "$sz"
    return 0
  fi
  printf "  [get]  %s\n" "$(basename "$out")"
  local code
  code=$(curl --fail --max-time 60 -sSL -w '%{http_code}' -o "$out" "$url" || true)
  if [[ "$code" != "200" ]] && [[ "$code" != "302" ]]; then
    printf "  [FAIL] HTTP %s for %s\n" "$code" "$url" >&2
    rm -f "$out"
    return 1
  fi
  if [[ ! -s "$out" ]]; then
    printf "  [FAIL] empty file at %s\n" "$out" >&2
    rm -f "$out"
    return 1
  fi
  local sz
  sz=$(stat -c '%s' "$out" 2>/dev/null || stat -f '%z' "$out")
  printf "         HTTP %s, %s bytes\n" "$code" "$sz"
}

echo "==> [1/3] Nazario 2023/2024/2025 mbox files"
for y in 2023 2024 2025; do
  _get "https://monkey.org/~jose/phishing/phishing-${y}" "$NZ_DIR/phishing-${y}.mbox"
done

echo
echo "==> [2/3] phishing_pot (git clone)"
if [[ -d "$PP_DIR/.git" ]]; then
  echo "  [skip] $PP_DIR already has a git checkout; pulling latest"
  git -C "$PP_DIR" pull --ff-only --quiet || {
    echo "  [warn] git pull failed; existing tree kept" >&2
  }
else
  if command -v git >/dev/null 2>&1; then
    echo "  [get]  cloning rf-peixoto/phishing_pot"
    git clone --depth 1 --quiet https://github.com/rf-peixoto/phishing_pot "$PP_DIR" || {
      echo "  [FAIL] git clone failed" >&2
      exit 1
    }
  else
    echo "  [FAIL] git not available, falling back to tarball download"
    _get "https://github.com/rf-peixoto/phishing_pot/archive/refs/heads/main.tar.gz" \
         "$PP_DIR/phishing_pot.tar.gz"
    tar -xzf "$PP_DIR/phishing_pot.tar.gz" -C "$PP_DIR" --strip-components=1
  fi
fi
echo "         phishing_pot eml count: $(find "$PP_DIR" -type f -name '*.eml' | wc -l)"

echo
echo "==> [3/3] Champa et al. 2024 curated dataset (Figshare)"
# Figshare article id 24899943, "Phishing Email Curated Datasets".
# The ndownloader endpoint streams the whole article as a zip.
_get "https://figshare.com/ndownloader/articles/24899943/versions/1" \
     "$CH_DIR/champa_24899943.zip"
if [[ -f "$CH_DIR/champa_24899943.zip" ]] && [[ -s "$CH_DIR/champa_24899943.zip" ]]; then
  echo "  [unzip] champa_24899943.zip"
  unzip -o -q "$CH_DIR/champa_24899943.zip" -d "$CH_DIR"
fi

echo
echo "Done. Layout:"
for f in "$NZ_DIR"/phishing-*.mbox; do
  if [[ -f "$f" ]]; then
    sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f")
    printf "  %-50s %s bytes\n" "${f#$ROOT/}" "$sz"
  fi
done
printf "  %-50s %s eml files\n" "data/raw/phishing_pot/" "$(find "$PP_DIR" -type f -name '*.eml' 2>/dev/null | wc -l)"
for f in "$CH_DIR"/*.csv "$CH_DIR"/*.zip; do
  [[ -f "$f" ]] || continue
  sz=$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f")
  printf "  %-50s %s bytes\n" "${f#$ROOT/}" "$sz"
done
