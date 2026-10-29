#!/usr/bin/env python3
"""Convert COMPASS-RT-style JSON findings to SARIF 2.1.0."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_TOOL = "COMPASS-RT"
DEFAULT_VERSION = "0.2"
DEFAULT_INFORMATION_URI = "https://github.com/nyght-x-walker/compass-sarif"
VALID_LEVELS = {"error", "warning", "note", "none"}


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _rule_name(rule_id: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]+", "_", rule_id).strip("_")
    return name or "finding"


def _relative_uri(uri: Any, repo_root: str | None) -> str | None:
    if not isinstance(uri, str) or not uri.strip():
        return None
    if uri.startswith(("http://", "https://")):
        return uri
    if os.path.isabs(uri) and repo_root:
        try:
            relative = os.path.relpath(uri, repo_root)
        except ValueError:
            return uri.replace(os.sep, "/")
        if not relative.startswith(".."):
            return relative.replace(os.sep, "/")
    return uri.replace(os.sep, "/")


def _level(finding: dict[str, Any]) -> tuple[str, str | None]:
    raw = finding.get("level", "warning")
    if not isinstance(raw, str):
        return "warning", None
    level = raw.strip().lower()
    if level in VALID_LEVELS:
        return level, None
    return "warning", raw


def _location(finding: dict[str, Any], repo_root: str | None) -> list[dict[str, Any]]:
    uri = _relative_uri(finding.get("uri"), repo_root)
    if not uri:
        return []
    region: dict[str, Any] = {}
    for key in ("startLine", "endLine", "startColumn", "endColumn"):
        value = finding.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            region[key] = value
    if "startLine" not in region:
        region["startLine"] = 1
    snippet = finding.get("snippet")
    if isinstance(snippet, str) and snippet.strip():
        region["snippet"] = {"text": snippet}
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": region,
            }
        }
    ]


def _rule(finding: dict[str, Any]) -> dict[str, Any]:
    rule_id = finding["ruleId"]
    rule_name = finding.get("ruleName")
    if not isinstance(rule_name, str) or not rule_name.strip():
        rule_name = _rule_name(rule_id)
    short_description = finding.get("shortDescription")
    if not isinstance(short_description, str) or not short_description.strip():
        short_description = rule_id
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_name,
        "shortDescription": {"text": short_description},
    }
    help_uri = finding.get("helpUri")
    if isinstance(help_uri, str) and help_uri.strip():
        rule["helpUri"] = help_uri
    return rule


def _fingerprint(rule_id: str, uri: str | None, message: str) -> str:
    payload = "\0".join([rule_id, uri or "", message])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_sarif(payload: Any, repo_root: str | None = None) -> dict[str, Any]:
    document = _mapping(payload, "input")
    tool_meta = _mapping(document.get("tool", {}), "tool")
    run_meta = _mapping(document.get("run", {}), "run")
    findings = document.get("findings", document.get("results"))
    if findings is None:
        raise ValueError('input must contain a "findings" list')
    findings = _list(findings, "findings")

    tool_name = tool_meta.get("name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        tool_name = DEFAULT_TOOL
    tool_version = tool_meta.get("version")
    if not isinstance(tool_version, str) or not tool_version.strip():
        tool_version = DEFAULT_VERSION
    information_uri = tool_meta.get("informationUri")
    if not isinstance(information_uri, str) or not information_uri.strip():
        information_uri = DEFAULT_INFORMATION_URI

    rules: list[dict[str, Any]] = []
    rule_indexes: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    target = run_meta.get("target")

    for index, raw_finding in enumerate(findings):
        finding = _mapping(raw_finding, f"findings[{index}]")
        rule_id = finding.get("ruleId")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(f'findings[{index}] is missing "ruleId"')
        message = finding.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ValueError(f'findings[{index}] is missing "message"')

        if rule_id not in rule_indexes:
            rule_indexes[rule_id] = len(rules)
            rules.append(_rule(finding))

        level, original_level = _level(finding)
        uri = _relative_uri(finding.get("uri"), repo_root)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_indexes[rule_id],
            "level": level,
            "message": {"text": message},
            "partialFingerprints": {
                "compassFinding/v1": _fingerprint(rule_id, uri, message)
            },
        }

        locations = _location(finding, repo_root)
        if locations:
            result["locations"] = locations

        properties = finding.get("properties")
        if isinstance(properties, dict) and properties:
            result["properties"] = dict(properties)
        if original_level:
            result.setdefault("properties", {})["originalLevel"] = original_level
        if isinstance(target, str) and target.strip():
            result.setdefault("properties", {})["target"] = target

        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": information_uri,
                "rules": rules,
            }
        },
        "results": results,
    }
    run_name = run_meta.get("name")
    if isinstance(run_name, str) and run_name.strip():
        run["automationDetails"] = {"id": run_name}
    if isinstance(target, str) and target.strip():
        run["properties"] = {"target": target}

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="compass-sarif",
        description="Convert COMPASS-RT-style JSON findings to SARIF 2.1.0.",
    )
    parser.add_argument("input", type=Path, help="Path to the findings JSON file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("compass.sarif"),
        help="Path to write the SARIF file (default: compass.sarif)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root used to make absolute source paths relative",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        sarif = build_sarif(
            payload,
            repo_root=str(args.repo_root.resolve()) if args.repo_root else None,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"compass-sarif: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
