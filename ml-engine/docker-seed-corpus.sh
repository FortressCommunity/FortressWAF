#!/bin/sh
# Seed the shared corpus volume from the bundled training data, without
# overwriting anything the collector has already written. Runs at start; a
# no-op when /corpus is already populated.
set -eu

SRC=/app/training/data
DST=/corpus

mkdir -p "$DST"

if [ ! -d "$SRC" ]; then
  echo "corpus-seed: no bundled data at $SRC, nothing to do"
  exit 0
fi

for cat_dir in "$SRC"/*/; do
  [ -d "$cat_dir" ] || continue
  name=$(basename "$cat_dir")
  mkdir -p "$DST/$name"
  for f in "$cat_dir"*.txt; do
    [ -e "$f" ] || continue
    target="$DST/$name/$(basename "$f")"
    if [ ! -f "$target" ]; then
      cp "$f" "$target"
      echo "corpus-seed: seeded $target"
    fi
  done
done

echo "corpus-seed: done"

# The WAF collector runs as a nonroot user (distroless uid 65534) and appends to
# this volume, so it must be writable by that user. Make the tree group/world
# writable; the volume is internal to the compose network.
chmod -R a+rwX "$DST" 2>/dev/null || true
