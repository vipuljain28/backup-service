"""Enterprise Automated Test Suite Runner with HTML Report Generation."""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone

# Import test functions
from backup_service.tests.test_catalog import test_catalog_lifecycle
from backup_service.tests.test_manifest import test_manifest_formatting
from backup_service.tests.test_retention import test_retention_sliding_window
from backup_service.tests.test_security import (
    test_vault_encryption_and_tamper_detection,
    test_password_hashing,
    test_auth_token_lifecycle,
    test_rbac_permission_matrix
)
from backup_service.tests.test_explorer import (
    test_path_sanitization_traversal_prevention,
    test_local_directory_exploration
)
from backup_service.tests.test_storage import (
    test_storage_factory_local,
    test_storage_factory_invalid_provider
)
from backup_service.tests.test_restore import test_archive_reconnection_and_restore

TEST_SUITES = [
    ("Catalog: ACID State Store & Soft Deletions", test_catalog_lifecycle),
    ("Manifest: Audit Generator & Retained Log", test_manifest_formatting),
    ("Retention: 10-Day Sliding Window Pruning", test_retention_sliding_window),
    ("Security: AES-256-GCM Cryptographic Vault", test_vault_encryption_and_tamper_detection),
    ("Security: PBKDF2 Password Hashing", test_password_hashing),
    ("Security: Signed Session Tokens", test_auth_token_lifecycle),
    ("Security: OWASP Compliant RBAC Matrix", test_rbac_permission_matrix),
    ("Explorer: OWASP Path Traversal Prevention", test_path_sanitization_traversal_prevention),
    ("Explorer: Local Directory Navigation", test_local_directory_exploration),
    ("Storage: Factory & Local Provider", test_storage_factory_local),
    ("Storage: Unknown Provider Exception", test_storage_factory_invalid_provider),
    ("Disaster Recovery: Archive Reconnect & Restore", test_archive_reconnection_and_restore),
]


def run_tests_and_generate_html_report() -> bool:
    results = []
    overall_start = time.time()

    print("=" * 80)
    print("ENTERPRISE BACKUP & RECOVERY PLATFORM: AUTOMATED TEST HARNESS")
    print("=" * 80)

    all_passed = True
    for name, func in TEST_SUITES:
        t0 = time.time()
        try:
            func()
            duration = (time.time() - t0) * 1000
            print(f" [PASS] {name} ({duration:.2f} ms)")
            results.append({"name": name, "status": "PASSED", "duration_ms": round(duration, 2), "error": None})
        except Exception as exc:
            duration = (time.time() - t0) * 1000
            print(f" [FAIL] {name}: {exc}")
            results.append({"name": name, "status": "FAILED", "duration_ms": round(duration, 2), "error": str(exc)})
            all_passed = False

    total_duration = time.time() - overall_start
    passed_count = sum(1 for r in results if r["status"] == "PASSED")
    total_count = len(results)

    print("=" * 80)
    print(f"TEST EXECUTION SUMMARY: {passed_count}/{total_count} PASSED in {total_duration:.2f}s")
    print("=" * 80)

    # Generate HTML Report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Automated Test Report - Enterprise Backup Service</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    h1 {{ margin-top: 0; color: #38bdf8; }}
    .summary {{ display: flex; gap: 20px; margin-bottom: 24px; }}
    .card {{ flex: 1; padding: 16px; border-radius: 8px; background: #334155; text-align: center; }}
    .pass {{ color: #4ade80; font-weight: bold; }}
    .fail {{ color: #f87171; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #475569; }}
    th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 11px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Enterprise Backup Platform - Test Execution Report</h1>
    <p>Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <div class="summary">
      <div class="card"><h3>Total Tests</h3><p style="font-size: 24px;">{total_count}</p></div>
      <div class="card"><h3>Passed</h3><p class="pass" style="font-size: 24px;">{passed_count}</p></div>
      <div class="card"><h3>Failed</h3><p class="fail" style="font-size: 24px;">{total_count - passed_count}</p></div>
      <div class="card"><h3>Duration</h3><p style="font-size: 24px;">{total_duration:.2f}s</p></div>
    </div>
    <table>
      <thead>
        <tr><th>Test Routine</th><th>Duration</th><th>Status</th></tr>
      </thead>
      <tbody>
        {"".join(f"<tr><td>{r['name']}</td><td>{r['duration_ms']} ms</td><td class='{r['status'].lower()}'>{r['status']}</td></tr>" for r in results)}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    report_path = Path(__file__).parent / "test_report.html"
    report_path.write_text(html_content, encoding="utf-8")
    print(f"\n[+] Generated HTML Test Report: {report_path.resolve()}\n")

    return all_passed


if __name__ == "__main__":
    success = run_tests_and_generate_html_report()
    sys.exit(0 if success else 1)
