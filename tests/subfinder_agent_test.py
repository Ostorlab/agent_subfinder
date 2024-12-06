"""Unittests for the Subfinder Agent."""

import pathlib

import pytest
from pytest_mock import plugin
import ruamel.yaml
from pyfakefs import fake_filesystem_unittest

from ostorlab.agent.message import message
from agent import subfinder_agent as sub_agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions


def testAgentSubfinder_whenFindsSubDomains_emitsBackFindings(
    subfinder_agent, agent_mock, agent_persist_mock, mocker
):
    """Unittest for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]

    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "somedomain.com"}
    )
    subfinder_agent.process(msg)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector == "v3.asset.domain_name", (
        agent_mock[0].data["name"] == "subdomain1"
    )


def testAgentSubfinder_whenDomainHasAlreadyBeenProcessed_theDomainIsSkipped(
    subfinder_agent, agent_persist_mock, agent_mock, mocker
):
    """Unittest for Agent Subfinder. When it receives a domain that has already been processed,
    the agent should skip it."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "somedomain.com"}
    )

    subfinder_agent.process(msg)
    subfinder_agent.process(msg)

    assert len(agent_mock) == 3


def testAgentSubfinder_withInvalidTLD_doNotRaiseAnException(
    subfinder_agent, agent_persist_mock, agent_mock
):
    """Unittest for Agent Subfinder, when the TLD is invalid, the agent exists without raising an exception."""
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "somedomain.invalidtld"}
    )

    subfinder_agent.process(msg)

    assert len(agent_mock) == 0


def testAgentSubfinder_whenMaxSubDomainsSet_emitsBackFindings(
    subfinder_agent_max_subdomains, agent_mock, agent_persist_mock, mocker
):
    """Unittest for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]

    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "somedomain.com"}
    )
    subfinder_agent_max_subdomains.process(msg)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.asset.domain_name", (
        agent_mock[0].data["name"] == "subdomain1"
    )


def testAgentSubfinder_always_callsSetVirusTotalKeyInInit(
    subfinder_definition: agent_definitions.AgentDefinition,
    subfinder_settings: runtime_definitions.AgentSettings,
    mocker: plugin.MockerFixture,
) -> None:
    """
    Test that the Subfinder agent correctly updates the provider configuration
    with the VirusTotal key.
    """
    mocker_set_virustotal_api_key = mocker.patch(
        "agent.subfinder_agent.set_virustotal_api_key"
    )

    sub_agent.SubfinderAgent(subfinder_definition, subfinder_settings)

    assert mocker_set_virustotal_api_key.called is True
    assert mocker_set_virustotal_api_key.call_args[0][0] == "Justrandomvalue"


def testSetVirusTotalApiKey_whenConfFileNotFound_returnNoneAndLogError(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that the provider configuration correctly handles a missing configuration file."""

    sub_agent.set_virustotal_api_key("existing_key", "test_not.yaml")

    assert "Configuration file not found at test_not.yaml." in caplog.text


def testSetVirusTotalApiKey_whenWriteConfigurationFail_handleWriteError(
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that the provider configuration handles a write error correctly and logs the failure."""
    mocker.patch("ruamel.yaml.main.YAML.dump", side_effect=IOError)

    sub_agent.set_virustotal_api_key(
        "existing_key",
        str(pathlib.Path(__file__).parent / "provider-config-virustotal.yaml"),
    )

    assert "Failed to write configuration file" in caplog.text


def testSetVirusTotalApiKey_createsSectionAndAddsKeyWhenNoSectionExists() -> None:
    """
    Test that the function creates a `virustotal` section and adds the key
    when it does not exist in the configuration.
    """
    real_file_path = (
        pathlib.Path(__file__).parent / "provider-config-no-virustotal.yaml"
    )
    fake_file_path = "/fake/path/provider-config-no-virustotal.yaml"
    file_contents = real_file_path.read_text()

    with fake_filesystem_unittest.Patcher() as patcher:
        patcher.fs.create_file(fake_file_path, contents=file_contents)

        sub_agent.set_virustotal_api_key("new_key", fake_file_path)

        yaml = ruamel.yaml.YAML(typ="safe")
        fake_file = pathlib.Path(fake_file_path)
        updated_config = yaml.load(fake_file.read_text()) or {}
        assert "virustotal" in updated_config
        assert updated_config["virustotal"] == ["new_key"]
        assert "sources" in updated_config and "virustotal" in updated_config["sources"]


def testSetVirusTotalApiKey_whenVirusTotalSectionExists_addsKeyToExistingSection() -> (
    None
):
    """
    Test that the function adds the key to the existing `virustotal` section
    when it already exists in the configuration.
    """
    real_file_path = pathlib.Path(__file__).parent / "provider-config-virustotal.yaml"
    fake_file_path = "/fake/path/provider-config-virustotal.yaml"
    file_contents = real_file_path.read_text()

    with fake_filesystem_unittest.Patcher() as patcher:
        patcher.fs.create_file(fake_file_path, contents=file_contents)

        sub_agent.set_virustotal_api_key("new_key", fake_file_path)

        yaml = ruamel.yaml.YAML(typ="safe")
        fake_file = pathlib.Path(fake_file_path)
        updated_config = yaml.load(fake_file.read_text()) or {}
        assert "virustotal" in updated_config
        assert updated_config["virustotal"] == ["example-api-key", "new_key"]
        assert "sources" in updated_config and "virustotal" in updated_config["sources"]


def testSetVirusTotalApiKey_whenKeyAlreadyExists_doesNotAddKeyAgain() -> None:
    """
    Test that the function does not add the key to the `virustotal` section
    when it already exists in the configuration.
    """
    real_file_path = pathlib.Path(__file__).parent / "provider-config-virustotal.yaml"
    fake_file_path = "/fake/path/provider-config-virustotal.yaml"
    file_contents = real_file_path.read_text()

    with fake_filesystem_unittest.Patcher() as patcher:
        patcher.fs.create_file(fake_file_path, contents=file_contents)

        sub_agent.set_virustotal_api_key("example-api-key", fake_file_path)

        yaml = ruamel.yaml.YAML(typ="safe")
        fake_file = pathlib.Path(fake_file_path)
        updated_config = yaml.load(fake_file.read_text()) or {}
        assert "virustotal" in updated_config
        assert updated_config["virustotal"] == ["example-api-key"]
        assert "sources" in updated_config and "virustotal" in updated_config["sources"]


def testSetVirusTotalApiKey_whenFileEmpty_createSourcesAndAddVirusTotalKey() -> None:
    """
    Test that the function creates a `sources` section and adds the `virustotal` key
    when the configuration file is empty.
    """
    fake_file_path = "/fake/path/provider-config-empty.yaml"

    with fake_filesystem_unittest.Patcher() as patcher:
        patcher.fs.create_file(fake_file_path, contents="")

        sub_agent.set_virustotal_api_key("new_key", fake_file_path)

        yaml = ruamel.yaml.YAML(typ="safe")
        fake_file = pathlib.Path(fake_file_path)
        updated_config = yaml.load(fake_file.read_text()) or {}
        assert "virustotal" in updated_config
        assert updated_config["virustotal"] == ["new_key"]
        assert "sources" in updated_config and "virustotal" in updated_config["sources"]
