# Software Management Test Summary

Date: 2026-06-23

## Summary
- Command run: `python -m pytest tests/unit/test_upload_limits.py tests/unit/test_sms_lifecycle.py tests/integration/test_software_management_upload_download.py -q --junitxml=reports/software_management_results.xml --html=reports/software_management_report.html -rA`
- Total tests run: 7
- Passed: 3
- Failed: 4

## Artifacts
- JUnit XML: [reports/software_management_results.xml](reports/software_management_results.xml)
- HTML report: [reports/software_management_report.html](reports/software_management_report.html)
- This summary: [reports/software_management_test_summary.md](reports/software_management_test_summary.md)

## Failures (short)
- `tests/unit/test_sms_lifecycle.py::test_sms_version_becomes_downloadable_only_after_scan_and_publish`
  - Error: `AttributeError: type object 'SoftwareStatus' has no attribute 'DRAFT'` (in `app/modules/software_management/software/software.py`)
- `tests/unit/test_sms_lifecycle.py::test_sms_owner_controlled_pricing_is_normalized`
  - Error: `AttributeError: type object 'SoftwareStatus' has no attribute 'DRAFT'`
- `tests/unit/test_sms_lifecycle.py::test_paid_download_requires_purchase`
  - Error: `AttributeError: type object 'SoftwareStatus' has no attribute 'DRAFT'`
- `tests/integration/test_software_management_upload_download.py::test_software_management_contract_routes_are_registered`
  - Error: `TypeError: 'FastAPI' object is not iterable` (integration test expects an iterable of routes)

## Next steps and suggestions
- Inspect `app/modules/software_management/software/enums` (or where `SoftwareStatus` is defined) to ensure `DRAFT` is defined.
- For the integration failure, check how the FastAPI `app` fixture is provided in the test — iterate `app.routes` or use `app.router.routes` instead of iterating `app`.
- If you want, I can open the failing files and propose/implement minimal fixes and re-run tests.

## How to re-run locally

In PowerShell (uses the configured venv python):

```powershell
cd c:\Users\HomePC\Desktop\PROJECT_T\techpulse_backend
c:/Users/HomePC/Desktop/PROJECT_T/techpulse_backend/venv/Scripts/python.exe -m pytest tests/unit/test_upload_limits.py tests/unit/test_sms_lifecycle.py tests/integration/test_software_management_upload_download.py -q --junitxml=reports/software_management_results.xml --html=reports/software_management_report.html -rA
```

