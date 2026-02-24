"""Tests for the policy testing framework.

Covers:
- Test file loading (valid, malformed, missing)
- Test runner (pass, fail, mixed)
- CLI test command integration
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_safe import AgentSafe
from agent_safe.cli.main import cli
from agent_safe.testing.runner import (
    PolicyTestError,
    load_test_file,
    load_test_files,
    run_tests,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")


def _safe() -> AgentSafe:
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
    )


def runner() -> CliRunner:
    return CliRunner()


# --- Test file loading ---


class TestLoadTestFile:
    def test_load_valid_file(self, tmp_path: Path):
        f = tmp_path / "tests.yaml"
        f.write_text(
            "tests:\n"
            "  - name: test-one\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: allow\n",
            encoding="utf-8",
        )
        cases = load_test_file(f)
        assert len(cases) == 1
        assert cases[0].name == "test-one"
        assert cases[0].action == "restart-deployment"
        assert cases[0].target == "dev/test-app"
        assert cases[0].params == {"namespace": "dev", "deployment": "app"}
        assert cases[0].expect == "allow"

    def test_load_multiple_cases(self, tmp_path: Path):
        f = tmp_path / "tests.yaml"
        f.write_text(
            "tests:\n"
            "  - name: case-a\n"
            "    action: restart-deployment\n"
            "    expect: deny\n"
            "  - name: case-b\n"
            "    action: scale-deployment\n"
            "    expect: allow\n",
            encoding="utf-8",
        )
        cases = load_test_file(f)
        assert len(cases) == 2
        assert cases[0].name == "case-a"
        assert cases[1].name == "case-b"

    def test_optional_fields_default_to_none(self, tmp_path: Path):
        f = tmp_path / "tests.yaml"
        f.write_text(
            "tests:\n"
            "  - name: minimal\n"
            "    action: restart-deployment\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        cases = load_test_file(f)
        assert cases[0].target is None
        assert cases[0].caller is None
        assert cases[0].params is None

    def test_missing_tests_key(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("something: else\n", encoding="utf-8")
        with pytest.raises(PolicyTestError, match="tests"):
            load_test_file(f)

    def test_tests_not_a_list(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("tests: not-a-list\n", encoding="utf-8")
        with pytest.raises(PolicyTestError, match="list"):
            load_test_file(f)

    def test_missing_name(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            "tests:\n"
            "  - action: restart-deployment\n"
            "    expect: allow\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyTestError, match="name"):
            load_test_file(f)

    def test_missing_action(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            "tests:\n"
            "  - name: bad-test\n"
            "    expect: allow\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyTestError, match="action"):
            load_test_file(f)

    def test_invalid_expect_value(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            "tests:\n"
            "  - name: bad-test\n"
            "    action: restart-deployment\n"
            "    expect: maybe\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyTestError, match="expect"):
            load_test_file(f)

    def test_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("tests: : bad\n", encoding="utf-8")
        with pytest.raises(PolicyTestError, match="YAML"):
            load_test_file(f)

    def test_entry_not_mapping(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            "tests:\n"
            "  - just a string\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyTestError, match="mapping"):
            load_test_file(f)


class TestLoadTestFiles:
    def test_load_from_directory(self, tmp_path: Path):
        (tmp_path / "a.yaml").write_text(
            "tests:\n"
            "  - name: from-a\n"
            "    action: restart-deployment\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        (tmp_path / "b.yml").write_text(
            "tests:\n"
            "  - name: from-b\n"
            "    action: scale-deployment\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        cases = load_test_files(tmp_path)
        assert len(cases) == 2
        names = {c.name for c in cases}
        assert names == {"from-a", "from-b"}

    def test_load_single_file(self, tmp_path: Path):
        f = tmp_path / "single.yaml"
        f.write_text(
            "tests:\n"
            "  - name: one\n"
            "    action: restart-deployment\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        cases = load_test_files(f)
        assert len(cases) == 1

    def test_nonexistent_path(self, tmp_path: Path):
        with pytest.raises(PolicyTestError, match="not found"):
            load_test_files(tmp_path / "nope")

    def test_empty_directory(self, tmp_path: Path):
        d = tmp_path / "empty"
        d.mkdir()
        with pytest.raises(PolicyTestError, match="No YAML"):
            load_test_files(d)


# --- Test runner ---


class TestRunTests:
    def test_all_pass(self):
        safe = _safe()
        cases = load_test_files(
            _PROJECT_ROOT / "tests" / "policy_tests"
        )
        suite = run_tests(safe, cases)
        assert suite.all_passed
        assert suite.total == 13
        assert suite.failed == 0

    def test_failing_test(self, tmp_path: Path):
        f = tmp_path / "fail.yaml"
        f.write_text(
            "tests:\n"
            "  - name: wrong-expectation\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        safe = _safe()
        cases = load_test_file(f)
        suite = run_tests(safe, cases)
        assert not suite.all_passed
        assert suite.failed == 1
        assert suite.results[0].actual == "allow"
        assert not suite.results[0].passed

    def test_mixed_results(self, tmp_path: Path):
        f = tmp_path / "mixed.yaml"
        f.write_text(
            "tests:\n"
            "  - name: should-pass\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: allow\n"
            "  - name: should-fail\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        safe = _safe()
        cases = load_test_file(f)
        suite = run_tests(safe, cases)
        assert suite.passed == 1
        assert suite.failed == 1
        assert suite.total == 2

    def test_caller_in_test_case(self, tmp_path: Path):
        f = tmp_path / "caller.yaml"
        f.write_text(
            "tests:\n"
            "  - name: with-caller\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    caller: some-agent\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: allow\n",
            encoding="utf-8",
        )
        safe = _safe()
        cases = load_test_file(f)
        suite = run_tests(safe, cases)
        assert suite.all_passed

    def test_empty_suite(self):
        safe = _safe()
        suite = run_tests(safe, [])
        assert suite.total == 0
        assert not suite.all_passed  # no tests = not "all passed"


# --- CLI test command ---


class TestTestCommand:
    def test_all_pass_exit_0(self):
        result = runner().invoke(cli, [
            "test", "tests/policy_tests/",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 0
        assert "passed" in result.output.lower()

    def test_failure_exit_1(self, tmp_path: Path):
        f = tmp_path / "fail.yaml"
        f.write_text(
            "tests:\n"
            "  - name: wrong\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        result = runner().invoke(cli, [
            "test", str(f),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "1 failed" in result.output

    def test_invalid_test_file_exit_1(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("not_tests: true\n", encoding="utf-8")
        result = runner().invoke(cli, [
            "test", str(f),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 1

    def test_missing_test_path_exit_1(self):
        result = runner().invoke(cli, [
            "test", "/nonexistent/path",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 1

    def test_output_shows_pass_and_fail(self, tmp_path: Path):
        f = tmp_path / "mixed.yaml"
        f.write_text(
            "tests:\n"
            "  - name: good-test\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: allow\n"
            "  - name: bad-test\n"
            "    action: restart-deployment\n"
            "    target: dev/test-app\n"
            "    params:\n"
            "      namespace: dev\n"
            "      deployment: app\n"
            "    expect: deny\n",
            encoding="utf-8",
        )
        result = runner().invoke(cli, [
            "test", str(f),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert "PASS" in result.output
        assert "FAIL" in result.output
        assert "good-test" in result.output
        assert "bad-test" in result.output
