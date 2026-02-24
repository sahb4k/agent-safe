"""Tests for AWS action YAML definitions (v0.9.0).

Validates that all AWS action files load correctly, have valid schemas,
proper credential scoping, and follow naming conventions.
"""

from __future__ import annotations

from pathlib import Path

from agent_safe.registry.loader import load_registry

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")

AWS_ACTION_NAMES = [
    "ec2-stop-instance",
    "ec2-start-instance",
    "ec2-reboot-instance",
    "ec2-terminate-instance",
    "ecs-update-service",
    "ecs-stop-task",
    "ecs-scale-service",
    "lambda-update-function-config",
    "lambda-invoke-function",
    "s3-delete-object",
    "s3-put-bucket-policy",
    "iam-attach-role-policy",
    "iam-detach-role-policy",
]


# --- Loading Tests ---


class TestAwsActionLoading:
    def test_all_aws_actions_load(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert action is not None, f"Action {name} not found in registry"

    def test_total_action_count(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        # 20 K8s + 13 AWS = 33 total
        assert len(registry.list_actions()) == 33

    def test_no_duplicate_names(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        names = registry.list_actions()
        assert len(names) == len(set(names))

    def test_aws_actions_coexist_with_k8s(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        # K8s actions still work
        assert registry.get("restart-deployment") is not None
        # AWS actions also work
        assert registry.get("ec2-stop-instance") is not None

    def test_aws_action_files_exist(self) -> None:
        actions_path = Path(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            yaml_path = actions_path / f"{name}.yaml"
            assert yaml_path.exists(), f"Missing file: {yaml_path}"


# --- Schema Tests ---


class TestAwsActionSchema:
    def test_all_have_aws_target_type(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert any(
                t.startswith("aws-") for t in action.target_types
            ), f"{name} missing aws- target type"

    def test_all_have_region_parameter(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            param_names = [p.name for p in action.parameters]
            assert "region" in param_names, f"{name} missing region parameter"

    def test_all_have_valid_risk_class(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        valid_risks = {"low", "medium", "high", "critical"}
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert action.risk_class.value in valid_risks, (
                f"{name} has invalid risk_class: {action.risk_class}"
            )

    def test_all_have_aws_tag(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert "aws" in action.tags, f"{name} missing 'aws' tag"

    def test_critical_actions_are_correct(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        critical_actions = [
            "ec2-terminate-instance",
            "s3-put-bucket-policy",
            "iam-attach-role-policy",
            "iam-detach-role-policy",
        ]
        for name in critical_actions:
            action = registry.get(name)
            assert action.risk_class.value == "critical", (
                f"{name} should be critical, got {action.risk_class}"
            )


# --- Credential Tests ---


class TestAwsActionCredentials:
    def test_all_have_credentials_block(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert action.credentials is not None, f"{name} missing credentials block"

    def test_all_credentials_type_is_aws(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert action.credentials.type == "aws", (
                f"{name} credentials type should be 'aws', got '{action.credentials.type}'"
            )

    def test_all_credentials_have_actions_field(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            assert "actions" in action.credentials.fields, (
                f"{name} credentials missing 'actions' field"
            )


# --- Naming Convention Tests ---


class TestAwsActionNaming:
    def test_names_follow_service_prefix(self) -> None:
        valid_prefixes = ("ec2-", "ecs-", "lambda-", "s3-", "iam-")
        for name in AWS_ACTION_NAMES:
            assert any(
                name.startswith(p) for p in valid_prefixes
            ), f"{name} does not start with a valid AWS service prefix"

    def test_reversible_actions_have_rollback(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        for name in AWS_ACTION_NAMES:
            action = registry.get(name)
            if action.reversible:
                assert action.rollback_action is not None, (
                    f"{name} is reversible but missing rollback_action"
                )
