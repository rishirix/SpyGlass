#!/usr/bin/env bash
# Demo preflight: reseed the emulator, run one scan via the API, verify the numbers.
set -u
cd "$(dirname "$0")"
python seed_demo.py || { echo "SEED FAILED"; exit 1; }
curl -s -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" -H "X-Requested-With: Spyglass" -d '{}' \
| python -c "
import sys, json
s = json.load(sys.stdin)['scan']
print('scan', s['id'], '| mode', s['mode'], '| score', s['score'], '| pass/fail/warn/na',
      s['passed'], s['failed'], s['warnings'], s['not_assessed'])
ok = (s['mode'] == 'demo' and s['score'] == 55.6 and
      (s['passed'], s['failed'], s['warnings'], s['not_assessed']) == (24, 20, 7, 0))
print('PREFLIGHT', 'OK' if ok else 'MISMATCH - investigate before presenting')
"
