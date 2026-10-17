
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from trusted_activity import is_trusted_activity


tests = [
    {
        "name": "Backup inside allowed window",
        "activity": "backup",
        "timestamp": "2026-10-16T02:00:00",
        "expected": True,
    },
    {
        "name": "Backup outside allowed window",
        "activity": "backup",
        "timestamp": "2026-10-16T12:00:00",
        "expected": False,
    },
    {
        "name": "Maintenance inside allowed window",
        "activity": "maintenance",
        "timestamp": "2026-10-16T03:00:00",
        "expected": True,
    },
    {
        "name": "Maintenance outside allowed window",
        "activity": "maintenance",
        "timestamp": "2026-10-16T12:00:00",
        "expected": False,
    },
]

failures = 0

for test in tests:
    actual = is_trusted_activity(
        "192.168.1.50",
        test["activity"],
        test["timestamp"],
    )

    passed = actual == test["expected"]

    print(
        f"{'PASS' if passed else 'FAIL'}: {test['name']} | "
        f"expected={test['expected']} actual={actual}"
    )

    if not passed:
        failures += 1

print(f"\nTests run: {len(tests)}")
print(f"Failures: {failures}")

if failures:
    raise SystemExit(1)

print("PASS: Scheduled activity helper tests completed.")
