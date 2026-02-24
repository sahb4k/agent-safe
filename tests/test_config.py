"""Tests for Agent-Safe config loader (agent-safe.yaml)."""

from pathlib import Path

import pytest

from agent_safe.config import (
    AgentSafeConfig,
    find_config,
    generate_signing_key,
    load_config,
)

# --- generate_signing_key ---


class TestGenerateSigningKey:
    def test_returns_64_hex_chars(self):
        key = generate_signing_key()
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_unique_every_time(self):
        keys = {generate_signing_key() for _ in range(20)}
        assert len(keys) == 20


# --- find_config ---


class TestFindConfig:
    def test_finds_in_start_dir(self, tmp_path: Path):
        cfg = tmp_path / "agent-safe.yaml"
        cfg.write_text("registry: ./actions\n", encoding="utf-8")
        assert find_config(tmp_path) == cfg

    def test_finds_in_parent(self, tmp_path: Path):
        cfg = tmp_path / "agent-safe.yaml"
        cfg.write_text("registry: ./actions\n", encoding="utf-8")
        child = tmp_path / "sub" / "deep"
        child.mkdir(parents=True)
        assert find_config(child) == cfg

    def test_returns_none_when_missing(self, tmp_path: Path):
        assert find_config(tmp_path) is None

    def test_defaults_to_cwd(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert find_config() is None  # no config here

    def test_ignores_directories_named_config(self, tmp_path: Path):
        """A directory named agent-safe.yaml should not match."""
        (tmp_path / "agent-safe.yaml").mkdir()
        assert find_config(tmp_path) is None


# --- load_config ---


class TestLoadConfig:
    def test_explicit_path(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text(
            "registry: ./actions\npolicies: ./policies\n"
            "signing_key: abc123\n",
            encoding="utf-8",
        )
        cfg = load_config(cfg_path)
        assert cfg.config_path == cfg_path
        assert cfg.registry == str((tmp_path / "actions").resolve())
        assert cfg.policies == str((tmp_path / "policies").resolve())
        assert cfg.signing_key == "abc123"

    def test_explicit_path_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_config(tmp_path / "nope.yaml")

    def test_auto_discover(self, tmp_path: Path, monkeypatch):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("registry: ./my-actions\n", encoding="utf-8")
        child = tmp_path / "sub"
        child.mkdir()
        monkeypatch.chdir(child)
        cfg = load_config()
        assert cfg.config_path == cfg_path
        assert cfg.registry == str((tmp_path / "my-actions").resolve())

    def test_auto_discover_disabled(self, tmp_path: Path, monkeypatch):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("registry: ./actions\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        cfg = load_config(auto_discover=False)
        assert cfg.config_path is None
        assert cfg.registry is None

    def test_empty_config_returns_defaults(self, tmp_path: Path):
        cfg = load_config(auto_discover=False)
        assert cfg == AgentSafeConfig()
        assert cfg.registry is None
        assert cfg.signing_key is None

    def test_resolves_paths_relative_to_yaml(self, tmp_path: Path):
        sub = tmp_path / "config-dir"
        sub.mkdir()
        cfg_path = sub / "agent-safe.yaml"
        cfg_path.write_text(
            "registry: ../actions\ninventory: ./inv.yaml\n",
            encoding="utf-8",
        )
        cfg = load_config(cfg_path)
        assert cfg.registry == str((tmp_path / "actions").resolve())
        assert cfg.inventory == str((sub / "inv.yaml").resolve())

    def test_missing_keys_are_none(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("issuer: custom\n", encoding="utf-8")
        cfg = load_config(cfg_path)
        assert cfg.registry is None
        assert cfg.policies is None
        assert cfg.signing_key is None
        assert cfg.issuer == "custom"

    def test_empty_yaml_file(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("", encoding="utf-8")
        cfg = load_config(cfg_path)
        assert cfg.config_path == cfg_path
        assert cfg.registry is None

    def test_non_mapping_raises(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("- item\n- item2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            load_config(cfg_path)

    def test_all_fields(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text(
            "registry: ./actions\n"
            "policies: ./policies\n"
            "inventory: ./inv.yaml\n"
            "audit_log: ./audit.jsonl\n"
            "signing_key: deadbeef\n"
            "issuer: my-org\n"
            "rate_limit:\n  max_requests: 10\n"
            "cumulative_risk:\n  window_seconds: 300\n",
            encoding="utf-8",
        )
        cfg = load_config(cfg_path)
        assert cfg.signing_key == "deadbeef"
        assert cfg.issuer == "my-org"
        assert cfg.rate_limit == {"max_requests": 10}
        assert cfg.cumulative_risk == {"window_seconds": 300}

    def test_string_path_accepted(self, tmp_path: Path):
        cfg_path = tmp_path / "agent-safe.yaml"
        cfg_path.write_text("registry: ./actions\n", encoding="utf-8")
        cfg = load_config(str(cfg_path))
        assert cfg.config_path == cfg_path


# --- AgentSafeConfig immutability ---


class TestAgentSafeConfigFrozen:
    def test_frozen(self):
        cfg = AgentSafeConfig()
        with pytest.raises(AttributeError):
            cfg.registry = "something"  # type: ignore[misc]
