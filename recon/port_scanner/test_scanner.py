import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import (
    ScanResult,
    build_results,
    save_results,
    service_name,
    validate_scan_options,
)


class ScannerTests(unittest.TestCase):
    def test_known_service_name(self) -> None:
        self.assertEqual(service_name(80), "HTTP")
        self.assertEqual(service_name(22), "SSH")

    def test_validate_scan_options_rejects_invalid_port_range(self) -> None:
        with self.assertRaises(ValueError):
            validate_scan_options(100, 50, 1.0, 10)

    def test_validate_scan_options_rejects_invalid_timeout(self) -> None:
        with self.assertRaises(ValueError):
            validate_scan_options(1, 100, 0, 10)

    def test_build_results_adds_service_names(self) -> None:
        results = build_results([22, 80])

        self.assertEqual(
            results,
            [
                ScanResult(port=22, service="SSH"),
                ScanResult(port=80, service="HTTP"),
            ],
        )

    def test_save_results_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "scan.json"
            save_results(
                output_path=output_path,
                output_format="json",
                target="127.0.0.1",
                ip_address="127.0.0.1",
                start_port=1,
                end_port=100,
                elapsed=0.1234,
                results=[ScanResult(port=80, service="HTTP")],
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["target"], "127.0.0.1")
        self.assertEqual(payload["open_ports"][0]["port"], 80)
        self.assertEqual(payload["open_ports"][0]["service"], "HTTP")


if __name__ == "__main__":
    unittest.main()
