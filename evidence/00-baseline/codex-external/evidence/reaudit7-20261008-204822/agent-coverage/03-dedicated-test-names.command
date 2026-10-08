set -o pipefail; for f in system/tests/test_ac_*.py; do echo "=== $f ==="; rg -n "^def test_|^class Test" "$f"; done; echo COUNT; rg -n "^def test_" system/tests/test_ac_*.py | wc -l
