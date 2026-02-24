"""Policy test runner.

Loads YAML test case files, evaluates each case against the policy engine,
and reports pass/fail results.

Test file format::

    tests:
      - name: dev-is-allowed
        action: restart-deployment
        target: dev/test-app
        params:
          namespace: dev
          deployment: app
        expect: allow

      - name: prod-requires-approval
        action: restart-deployment
        target: prod/api-server
        params:
          namespace: prod
          deployment: api
        expect: require_approval
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_safe.models import DecisionResult
from agent_safe.sdk.client import AgentSafe


class PolicyTestError(Exception):
    """Raised when a test file is malformed."""


@dataclass
class TestCase:
    """A single policy test case."""

    name: str
    action: str
    target: str | None = None
    caller: str | None = None
    params: dict[str, Any] | None = None
    expect: str = ""  # "allow", "deny", or "require_approval"
    source_file: str = ""
    ticket_id: str | None = None


@dataclass
class TestResult:
    """Result of running a single test case."""

    case: TestCase
    passed: bool
    actual: str = ""
    reason: str = ""


@dataclass
class TestSuiteResult:
    """Aggregated results from running all test files."""

    results: list[TestResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.total > 0


_VALID_EXPECTS = {"allow", "deny", "require_approval"}


def load_test_file(path: Path) -> list[TestCase]:
    """Load test cases from a YAML file.

    The file must have a top-level ``tests:`` key containing a list of
    test case mappings.

    Raises:
        PolicyTestError: If the file is malformed.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PolicyTestError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict) or "tests" not in data:
        raise PolicyTestError(f"{path}: must have a top-level 'tests' key")

    tests_raw = data["tests"]
    if not isinstance(tests_raw, list):
        raise PolicyTestError(f"{path}: 'tests' must be a list")

    cases: list[TestCase] = []
    for i, entry in enumerate(tests_raw):
        if not isinstance(entry, dict):
            raise PolicyTestError(f"{path}: test #{i + 1} must be a mapping")

        name = entry.get("name")
        if not name:
            raise PolicyTestError(f"{path}: test #{i + 1} missing 'name'")

        action = entry.get("action")
        if not action:
            raise PolicyTestError(f"{path}: test '{name}' missing 'action'")

        expect = entry.get("expect", "")
        if expect not in _VALID_EXPECTS:
            raise PolicyTestError(
                f"{path}: test '{name}' has invalid expect '{expect}'. "
                f"Must be one of: {', '.join(sorted(_VALID_EXPECTS))}"
            )

        cases.append(TestCase(
            name=name,
            action=action,
            target=entry.get("target"),
            caller=entry.get("caller"),
            params=entry.get("params"),
            expect=expect,
            source_file=str(path),
            ticket_id=entry.get("ticket_id"),
        ))

    return cases


def load_test_files(path: Path) -> list[TestCase]:
    """Load test cases from a file or directory.

    If ``path`` is a directory, all ``*.yaml`` and ``*.yml`` files are loaded.
    If ``path`` is a file, just that file is loaded.

    Raises:
        PolicyTestError: If any file is malformed or path doesn't exist.
    """
    if not path.exists():
        raise PolicyTestError(f"Test path not found: {path}")

    if path.is_file():
        return load_test_file(path)

    # Directory: collect all YAML files
    files = sorted(
        list(path.glob("*.yaml")) + list(path.glob("*.yml"))
    )
    if not files:
        raise PolicyTestError(f"No YAML test files found in {path}")

    cases: list[TestCase] = []
    for f in files:
        cases.extend(load_test_file(f))
    return cases


def run_tests(safe: AgentSafe, cases: list[TestCase]) -> TestSuiteResult:
    """Run all test cases against the policy engine.

    Returns a TestSuiteResult with individual pass/fail results.
    """
    suite = TestSuiteResult()

    expect_map = {
        "allow": DecisionResult.ALLOW,
        "deny": DecisionResult.DENY,
        "require_approval": DecisionResult.REQUIRE_APPROVAL,
    }

    for case in cases:
        decision = safe.check(
            action=case.action,
            target=case.target,
            caller=case.caller,
            params=case.params,
            ticket_id=case.ticket_id,
        )

        expected = expect_map[case.expect]
        passed = decision.result == expected

        suite.results.append(TestResult(
            case=case,
            passed=passed,
            actual=decision.result.value,
            reason=decision.reason,
        ))

    return suite
