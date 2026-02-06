"""Unit tests for ProviderConfigManager."""

import pathlib

import pytest
import ruamel.yaml
from pyfakefs import fake_filesystem_unittest
from pytest_mock import plugin

from agent import provider_config_manager


def _load_yaml(path: str) -> dict:
    yaml = ruamel.yaml.YAML(typ="safe")
    return yaml.load(pathlib.Path(path).read_text()) or {}


def testAddProviderKey_whenProviderNameEmpty_logsErrorAndReturns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = provider_config_manager.ProviderConfigManager(config_path="dummy.yaml")

    manager.add_provider_key("", "apikey")

    assert "Provider name cannot be empty." in caplog.text


def testAddProviderKey_whenApiKeyEmpty_logsErrorAndReturns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = provider_config_manager.ProviderConfigManager(config_path="dummy.yaml")

    manager.add_provider_key("virustotal", "")

    assert "API key cannot be empty for provider 'virustotal'." in caplog.text


def testAddProviderKey_whenConfigFileNotFound_logsError(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = provider_config_manager.ProviderConfigManager(
        config_path="/fake/path/config.yaml"
    )

    manager.add_provider_key("virustotal", "new_key")

    assert "Configuration file not found at" in caplog.text


def testAddProviderKey_whenFileEmpty_createsProviderSection() -> None:
    fake_path = "/fake/path/config.yaml"

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents="")

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "new_key")

        config = _load_yaml(fake_path)
        assert config["virustotal"] == ["new_key"]


def testAddProviderKey_whenProviderDoesNotExist_createsNewSection() -> None:
    fake_path = "/fake/path/config.yaml"
    contents = """
shodan:
  - existing_key
"""

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents=contents)

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "new_key")

        config = _load_yaml(fake_path)
        assert config["virustotal"] == ["new_key"]
        assert config["shodan"] == ["existing_key"]


def testAddProviderKey_whenProviderExists_appendsKey() -> None:
    fake_path = "/fake/path/config.yaml"
    contents = """
virustotal:
  - old_key
"""

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents=contents)

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "new_key")

        config = _load_yaml(fake_path)
        assert config["virustotal"] == ["old_key", "new_key"]


def testAddProviderKey_whenKeyAlreadyExists_doesNotDuplicate() -> None:
    fake_path = "/fake/path/config.yaml"
    contents = """
virustotal:
  - existing_key
"""

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents=contents)

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "existing_key")

        config = _load_yaml(fake_path)
        assert config["virustotal"] == ["existing_key"]


def testAddProviderKey_whenYamlInvalid_logsParseError(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_path = "/fake/path/config.yaml"
    invalid_yaml = "virustotal: [unclosed"

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents=invalid_yaml)

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "new_key")

        assert "Failed to parse configuration file" in caplog.text


def testAddProviderKey_whenWriteFails_logsError(
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake_path = "/fake/path/config.yaml"

    with fake_filesystem_unittest.Patcher() as patcher:
        assert patcher.fs is not None
        patcher.fs.create_file(fake_path, contents="")

        mocker.patch(
            "ruamel.yaml.main.YAML.dump",
            side_effect=IOError("disk full"),
        )

        manager = provider_config_manager.ProviderConfigManager(config_path=fake_path)
        manager.add_provider_key("virustotal", "new_key")

        assert "Failed to write configuration file" in caplog.text
