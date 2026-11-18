import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import check_rules  # noqa: E402

GOOD = ROOT / "rules/sigma/linux/ssh_bruteforce_from_lab_vlan.yml"


@pytest.fixture()
def repo(tmp_path):
    (tmp_path / "rules/sigma").mkdir(parents=True)
    shutil.copy(GOOD, tmp_path / "rules/sigma/rule.yml")
    shutil.copytree(ROOT / "fixtures", tmp_path / "fixtures")
    return tmp_path


def test_the_real_repo_passes():
    assert check_rules.check(ROOT) == []


def test_strict_mode_flags_missing_fixtures():
    assert any("sudoers" in p for p in check_rules.check(ROOT, strict=True))


def test_good_rule_passes(repo):
    assert check_rules.check(repo) == []


def test_missing_technique_tag(repo):
    rule = repo / "rules/sigma/rule.yml"
    rule.write_text(rule.read_text().replace("  - attack.t1110.001\n", ""))
    assert any("ATT&CK technique" in p for p in check_rules.check(repo))


def test_duplicate_ids(repo):
    shutil.copy(GOOD, repo / "rules/sigma/copy.yml")
    assert any("also used by" in p for p in check_rules.check(repo))


def test_missing_fixtures(repo):
    shutil.rmtree(repo / "fixtures")
    assert any("needs fixtures" in p for p in check_rules.check(repo))


def test_unparseable_rule(repo):
    (repo / "rules/sigma/rule.yml").write_text("title: broken\ndetection: [\n")
    assert any("does not parse" in p for p in check_rules.check(repo))
