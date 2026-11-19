#!/usr/bin/env bash
# One command from a clean checkout: audit the planted estate, audit the clean
# control, verify both, prove the negative control, then run the acceptance suite.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-python3}"

echo "== 1. audit the planted estate (12 workflows)"
"$PY" audit.py audit fixtures/estate_12.json --claims fixtures/claims.json --out out/estate_12

echo
echo "== 2. audit the clean control (4 workflows, no planted faults)"
"$PY" audit.py audit fixtures/estate_clean.json --out out/estate_clean

echo
echo "== 3. re-derive every finding from the export"
"$PY" audit.py verify fixtures/estate_12.json out/estate_12/findings.json
"$PY" audit.py verify fixtures/estate_clean.json out/estate_clean/findings.json

echo
echo "== 4. negative control: delete a cited node and verify must fail"
"$PY" - <<'PYEOF'
import json
export = json.load(open("fixtures/estate_12.json"))
findings = json.load(open("out/estate_12/findings.json"))["findings"]
target = next(f for f in findings if f["pointer"].count("/") >= 3)
p = target["pointer"].strip("/").split("/")
wi, ni = int(p[0]), int(p[2])
print(f"   removing {export[wi]['nodes'][ni]['name']!r} from {export[wi]['name']!r}")
del export[wi]["nodes"][ni]
json.dump(export, open("out/estate_12_broken.json", "w"), indent=1)
PYEOF
if "$PY" audit.py verify out/estate_12_broken.json out/estate_12/findings.json; then
  echo "   FAIL: verification passed after the cited node was deleted" >&2
  exit 1
else
  echo "   OK: verification failed, as it must"
fi

echo
echo "== 5. acceptance suite"
"$PY" tools/acceptance.py

echo
echo "Artifacts: out/estate_12/{findings.json,inventory.json,report.md,report.pdf}"
