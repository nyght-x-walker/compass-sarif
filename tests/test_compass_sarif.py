import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import compass_sarif


ROOT = Path(__file__).resolve().parents[1]


def payload(*findings, **run):
    return {
        "tool": {"name": "COMPASS-RT", "version": "0.2"},
        "run": run,
        "findings": list(findings),
    }


class BuildSarifTests(unittest.TestCase):
    def test_minimal_finding(self):
        sarif = compass_sarif.build_sarif(
            payload(
                {
                    "ruleId": "LLM01.prompt-injection",
                    "message": "Direct prompt injection changed behavior.",
                    "uri": "app/chat.py",
                    "startLine": 42,
                }
            )
        )

        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "COMPASS-RT")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "LLM01.prompt-injection")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "LLM01.prompt-injection")
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app/chat.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 42)

    def test_rules_are_deduplicated(self):
        sarif = compass_sarif.build_sarif(
            payload(
                {"ruleId": "LLM01", "message": "first"},
                {"ruleId": "LLM01", "message": "second"},
            )
        )

        run = sarif["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][1]["ruleIndex"], 0)

    def test_missing_location_is_allowed(self):
        sarif = compass_sarif.build_sarif(
            payload({"ruleId": "LLM02", "message": "No source location"})
        )

        self.assertNotIn("locations", sarif["runs"][0]["results"][0])

    def test_absolute_uri_is_made_relative_to_repo_root(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "app" / "main.py"
            sarif = compass_sarif.build_sarif(
                payload(
                    {
                        "ruleId": "LLM03",
                        "message": "Absolute path",
                        "uri": str(source),
                        "startLine": 3,
                    }
                ),
                repo_root=str(repo),
            )

        location = sarif["runs"][0]["results"][0]["locations"][0]
        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"], "app/main.py")

    def test_unknown_level_falls_back_to_warning(self):
        sarif = compass_sarif.build_sarif(
            payload({"ruleId": "LLM04", "message": "Unknown level", "level": "critical"})
        )

        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "warning")
        self.assertEqual(result["properties"]["originalLevel"], "critical")

    def test_target_is_attached_to_results(self):
        sarif = compass_sarif.build_sarif(
            payload({"ruleId": "LLM05", "message": "Target"}, target="chat")
        )

        run = sarif["runs"][0]
        self.assertEqual(run["properties"]["target"], "chat")
        self.assertEqual(run["results"][0]["properties"]["target"], "chat")

    def test_missing_rule_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ruleId"):
            compass_sarif.build_sarif(payload({"message": "No rule"}))

    def test_missing_message_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "message"):
            compass_sarif.build_sarif(payload({"ruleId": "LLM06"}))

    def test_fingerprint_is_stable(self):
        finding = {"ruleId": "LLM07", "message": "Stable", "uri": "app/x.py"}
        first = compass_sarif.build_sarif(payload(finding))["runs"][0]["results"][0]
        second = compass_sarif.build_sarif(payload(dict(finding)))["runs"][0]["results"][0]

        self.assertEqual(
            first["partialFingerprints"]["compassFinding/v1"],
            second["partialFingerprints"]["compassFinding/v1"],
        )


class CliTests(unittest.TestCase):
    def test_cli_writes_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_path = directory / "findings.json"
            output_path = directory / "compass.sarif"
            input_path.write_text(
                json.dumps(
                    payload(
                        {
                            "ruleId": "LLM08",
                            "message": "CLI finding",
                            "uri": "app/cli.py",
                            "startLine": 1,
                        }
                    )
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "compass_sarif.py"),
                    str(input_path),
                    "-o",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            sarif = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "LLM08")

    def test_cli_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_path = directory / "findings.json"
            input_path.write_text("{", encoding="utf-8")

            completed = subprocess.run(
                [sys.executable, str(ROOT / "compass_sarif.py"), str(input_path)],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("compass-sarif:", completed.stderr)


if __name__ == "__main__":
    unittest.main()
