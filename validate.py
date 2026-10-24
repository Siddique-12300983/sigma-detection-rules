#!/usr/bin/env python3
"""Validate the Sigma rules in rules/.

Checks that each file is valid YAML and has the fields a Sigma rule needs:
a title, a UUID id, a logsource, and a detection block with a condition.
Exits non-zero if any rule is malformed, so it can gate CI.
"""

from __future__ import annotations

import pathlib
import sys
import uuid

import yaml

RULES_DIR = pathlib.Path(__file__).resolve().parent / "rules"
REQUIRED_TOP = ("title", "id", "description", "logsource", "detection", "level")


def validate_rule(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [f"invalid YAML: {exc}"]

    if not isinstance(doc, dict):
        return ["top level is not a mapping"]

    for key in REQUIRED_TOP:
        if key not in doc:
            errors.append(f"missing top-level key: {key}")

    rule_id = doc.get("id")
    if rule_id is not None:
        try:
            uuid.UUID(str(rule_id))
        except ValueError:
            errors.append(f"id is not a valid UUID: {rule_id}")

    detection = doc.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection block has no condition")
        selections = [k for k in detection if k != "condition"]
        if not selections:
            errors.append("detection block has no selection")
    elif detection is not None:
        errors.append("detection is not a mapping")

    level = doc.get("level")
    if level is not None and level not in ("informational", "low", "medium", "high", "critical"):
        errors.append(f"unexpected level: {level}")

    return errors


def main() -> int:
    rule_files = sorted(RULES_DIR.glob("*.yml")) + sorted(RULES_DIR.glob("*.yaml"))
    if not rule_files:
        print("no rule files found in rules/", file=sys.stderr)
        return 1

    ok = True
    for path in rule_files:
        errors = validate_rule(path)
        if errors:
            ok = False
            print(f"FAIL {path.name}")
            for e in errors:
                print(f"       - {e}")
        else:
            print(f"OK   {path.name}")

    print()
    print(f"{len(rule_files)} rule(s) checked")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
