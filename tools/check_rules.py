"""Checks every Sigma rule before it can merge.

- parses with pySigma (the same parser the converters use)
- has an id, a status, a level and a description
- carries at least one ATT&CK technique tag (attack.t1234 or attack.t1234.001)
- has a fixtures folder named after its id, with a match.log and a no_match.log
  (or a README.md saying what fixtures are still needed, which fails with --strict)
- no two rules share an id

Usage: python tools/check_rules.py [--strict] [repo root]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def check(root: Path, strict: bool = False) -> list[str]:
    problems: list[str] = []
    seen: dict[str, Path] = {}
    rule_files = sorted((root / "rules" / "sigma").rglob("*.yml"))
    if not rule_files:
        return ["No Sigma rules found under rules/sigma"]

    for path in rule_files:
        name = path.relative_to(root)
        try:
            rules = SigmaCollection.from_yaml(path.read_text()).rules
        except (SigmaError, yaml.YAMLError) as exc:
            problems.append(f"{name}: does not parse: {exc}")
            continue
        for rule in rules:
            rule_id = str(rule.id) if rule.id else ""
            if not rule_id:
                problems.append(f"{name}: missing id")
                continue
            if rule_id in seen:
                problems.append(f"{name}: id {rule_id} is also used by {seen[rule_id]}")
            seen[rule_id] = name
            for field in ("status", "level", "description"):
                if not getattr(rule, field, None):
                    problems.append(f"{name}: missing {field}")
            tags = [f"{t.namespace}.{t.name}" for t in rule.tags]
            if not any(TECHNIQUE.match(t) for t in tags):
                problems.append(f"{name}: needs an ATT&CK technique tag like attack.t1110.001")

            fixtures = root / "fixtures" / rule_id
            has_pair = (fixtures / "match.log").is_file() and (fixtures / "no_match.log").is_file()
            if not has_pair:
                if (fixtures / "README.md").is_file() and not strict:
                    continue
                problems.append(f"{name}: needs fixtures/{rule_id}/match.log and no_match.log")
    return problems


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    problems = check(root, strict)
    for problem in problems:
        print(problem)
    print(f"{len(problems)} problem(s)" if problems else "All rules OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
