"""Run a real scan, persist it, and read it back. Usage: python test_scan_persist.py <url>"""
import sys

from app import app
import scanner
from models import get_recent_scans, get_scan_by_id, save_scan_result


def main(url):
    with app.app_context():
        result = scanner.scan(url)
        print(f"Scanned {result['target_url']}: {result['security_score']}/100 ({result['risk_level']})")

        saved = save_scan_result(result)
        print(f"Saved as scan_id={saved.scan_id} with {len(saved.findings)} findings")

        fetched = get_scan_by_id(saved.scan_id)
        assert fetched is not None, "scan not found after save"
        assert fetched.target_url == result["target_url"]
        assert fetched.security_score == result["security_score"]
        assert fetched.risk_level == result["risk_level"]
        assert len(fetched.findings) == len(result["findings"])
        print(f"Read back scan_id={fetched.scan_id}: matches saved data")

        recent = get_recent_scans(limit=5)
        print(f"Recent scans ({len(recent)}):")
        for s in recent:
            print(f"  scan_id={s.scan_id} {s.target_url} -> {s.security_score}/100 ({s.risk_level})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_scan_persist.py <target_url>")
        sys.exit(1)
    main(sys.argv[1])
