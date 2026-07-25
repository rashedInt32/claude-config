#!/usr/bin/env bash
# check-deny-drift.sh -- warn when the published example carries weaker `deny`
# rules than the real config it mirrors.
#
# settings.example.json is a hand-maintained mirror of ~/.claude/settings.json.
# The `deny` list is the part that carries real security weight (secrets, sudo,
# rm -rf), so when a rule lands in the real config but not the example, everyone
# who adopts this repo gets less protection than the maintainer already decided
# they needed. That direction is the one worth catching.
#
# Warn-only by design: it prints and exits 0. These very settings deny
# `git commit --no-verify`, so a blocking hook would be a trap with no exit.
# To make it block anyway, change the final `exit 0` to `exit 1`.
#
# Point it at a different real config with CLAUDE_SETTINGS=/path/to/settings.json.

set -uo pipefail

real="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"

# No real config to compare against (fresh clone, CI, another machine) is the
# normal case for anyone but the maintainer -- silence, not an error.
[ -f "$real" ] || exit 0
command -v python3 >/dev/null 2>&1 || exit 0

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -n "$repo_root" ] || exit 0
[ -f "$repo_root/settings.example.json" ] || exit 0

# Compare what would actually be committed (the index), not the working tree,
# falling back to the file itself if it isn't tracked yet.
tmp=$(mktemp) || exit 0
trap 'rm -f "$tmp"' EXIT
if ! git -C "$repo_root" show :settings.example.json >"$tmp" 2>/dev/null; then
  cp "$repo_root/settings.example.json" "$tmp" 2>/dev/null || exit 0
fi

python3 - "$real" "$tmp" <<'PY'
import json, sys

def deny(path):
    with open(path) as f:
        return json.load(f).get("permissions", {}).get("deny", [])

try:
    real, example = deny(sys.argv[1]), deny(sys.argv[2])
except Exception as exc:
    print(f"check-deny-drift: could not read settings ({exc}) -- skipping")
    sys.exit(0)

missing = [rule for rule in real if rule not in example]
extra = [rule for rule in example if rule not in real]

if not missing and not extra:
    sys.exit(0)

print()
print("  check-deny-drift: settings.example.json `deny` has drifted")

if missing:
    print()
    print(f"  {len(missing)} rule(s) in your real config but NOT in the published example --")
    print("  anyone adopting this repo gets weaker protection than you run:")
    for rule in missing:
        print(f"      + {rule}")

if extra:
    print()
    print(f"  {len(extra)} rule(s) in the example but not in your real config --")
    print("  harmless, but the mirror is stale:")
    for rule in extra:
        print(f"      - {rule}")

print()
print("  Commit continues. Sync the two `permissions.deny` arrays when convenient.")
print()
PY

exit 0
