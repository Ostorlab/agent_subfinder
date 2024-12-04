"""Unittests for the Subfinder Agent."""

import pathlib

import pytest
from pytest_mock import plugin

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


def testAgentSubfinder_whenVirustotalKeyPassed_emitsBackFindings(
    subfinder_definition: agent_definitions.AgentDefinition,
    subfinder_settings: runtime_definitions.AgentSettings,
    mocker: plugin.MockerFixture,
) -> None:
    """
    Test that the Subfinder agent correctly updates the provider configuration
    with the VirusTotal key.
    """
    mocker_update_provider_config = mocker.patch(
        "agent.subfinder_agent.update_provider_config"
    )

    sub_agent.SubfinderAgent(subfinder_definition, subfinder_settings)

    assert mocker_update_provider_config.called is True
    assert mocker_update_provider_config.call_args[0][0] == "Justrandomvalue"


def testUpdateConfigurationFile_whenConfNotFound_handelFileNotFoundError(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that the provider configuration correctly handles a missing configuration file."""

    sub_agent.update_provider_config("existing_key", "test_not.yaml")

    assert "Configuration file not found. Creating a new one." in caplog.text


def testupdateconfigupdate_whenWriteConfigurationFail_handelWriteErro(
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that the provider configuration handles a write error correctly and logs the failure."""
    mocker.patch("ruamel.yaml.main.YAML.dump", side_effect=FileNotFoundError)

    sub_agent.update_provider_config(
        "existing_key", str(pathlib.Path(__file__).parent / "provider-config.yaml")
    )

    assert "Failed to write configuration file" in caplog.text
