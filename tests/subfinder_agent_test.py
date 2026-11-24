"""Unittests for the Subfinder Agent."""

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import subfinder_agent as sub_agent


def testAgentSubfinder_whenFindsSubDomains_emitsBackFindings(
    subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Unit test for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    subfinder_agent.process(domain_message)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector == "v3.asset.domain_name", (
        agent_mock[0].data["name"] == "subdomain1"
    )


def testAgentSubfinder_whenDomainHasAlreadyBeenProcessed_theDomainIsSkipped(
    subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Unit test for Agent Subfinder. When it receives a domain that has already been processed,
    the agent should skip it."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    subfinder_agent.process(domain_message)
    subfinder_agent.process(domain_message)

    assert len(agent_mock) == 3


def testAgentSubfinder_withInvalidTLD_doNotRaiseAnException(
    subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> None:
    """Unittest for Agent Subfinder, when the TLD is invalid, the agent exists without raising an exception."""
    del agent_persist_mock
    msg = message.Message.from_data(
        selector="v3.asset.domain_name", data={"name": "somedomain.invalidtld"}
    )

    subfinder_agent.process(msg)

    assert len(agent_mock) == 0


def testAgentSubfinder_whenMaxSubDomainsSet_emitsBackFindings(
    subfinder_agent_max_subdomains: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Unit test for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    subfinder_agent_max_subdomains.process(domain_message)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.asset.domain_name", (
        agent_mock[0].data["name"] == "subdomain1"
    )


def testAgentSubfinder_whenActiveArg_subfinderCommandShouldHaveActiveFlagSet(
    active_enumeration_subfinder: sub_agent.SubfinderAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Ensure that the `-active` & `-all` are set when the `use_all_sources` & `active_only` arguments are True."""
    del agent_persist_mock
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    active_enumeration_subfinder.process(message=domain_message)

    assert run_command_mock.called is True
    run_command_args = run_command_mock.call_args_list[0].kwargs
    subfinder_args = run_command_args["args"]
    assert "subfinder" in subfinder_args
    assert "-d" in subfinder_args
    assert "somedomain.com" in subfinder_args
    assert "-active" in subfinder_args
    assert "-all" in subfinder_args


def testUpdateProvidersApiKeys_whenValidApiKeyProvided_addsKeyToProviderConfig(
    subfinder_agent: sub_agent.SubfinderAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for update_providers_api_keys: when a valid API key is provided, it should be added to the provider config."""
    add_provider_key_mock = mocker.patch.object(
        sub_agent.provider_config_mgr, "add_provider_key"
    )
    args: dict[str, str | None] = {"virustotal_api_key": "test_api_key_123"}

    subfinder_agent.update_providers_api_keys(args)

    add_provider_key_mock.assert_called_once_with("virustotal", "test_api_key_123")


def testUpdateProvidersApiKeys_whenNoApiKeyProvided_skipsProvider(
    subfinder_agent: sub_agent.SubfinderAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for update_providers_api_keys: when no API key is provided for a provider argument, it should be skipped."""
    add_provider_key_mock = mocker.patch.object(
        sub_agent.provider_config_mgr, "add_provider_key"
    )
    args: dict[str, str | None] = {"virustotal_api_key": None, "shodan_api_key": ""}

    subfinder_agent.update_providers_api_keys(args)

    add_provider_key_mock.assert_not_called()


def testUpdateProvidersApiKeys_whenArgNotInProviderMap_skipsArg(
    subfinder_agent: sub_agent.SubfinderAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for update_providers_api_keys: when an argument is not in PROVIDER_ARG_MAP, it should be skipped."""
    add_provider_key_mock = mocker.patch.object(
        sub_agent.provider_config_mgr, "add_provider_key"
    )
    args: dict[str, str | None] = {
        "unknown_provider_api_key": "some_key",
        "random_arg": "value",
    }

    subfinder_agent.update_providers_api_keys(args)

    add_provider_key_mock.assert_not_called()


def testUpdateProvidersApiKeys_whenMultipleValidApiKeysProvided_addsAllKeysToProviderConfig(
    subfinder_agent: sub_agent.SubfinderAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for update_providers_api_keys: when multiple valid API keys are provided, all should be added."""
    add_provider_key_mock = mocker.patch.object(
        sub_agent.provider_config_mgr, "add_provider_key"
    )
    args: dict[str, str | None] = {
        "virustotal_api_key": "vt_key_123",
        "shodan_api_key": "shodan_key_456",
        "github_api_key": "github_key_789",
    }

    subfinder_agent.update_providers_api_keys(args)

    assert add_provider_key_mock.call_count == 3
    add_provider_key_mock.assert_any_call("virustotal", "vt_key_123")
    add_provider_key_mock.assert_any_call("shodan", "shodan_key_456")
    add_provider_key_mock.assert_any_call("github", "github_key_789")


def testAgentSubfinder_whenFindsSubdomains_logsFoundSubdomains(
    subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Unit test to ensure subdomain discovery logging is executed."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)
    logger_info_mock = mocker.patch("agent.subfinder_agent.logger.info")

    subfinder_agent.process(domain_message)

    assert len(agent_mock) == 2

    log_calls = [
        call
        for call in logger_info_mock.call_args_list
        if "Found subdomain" in str(call)
    ]
    assert len(log_calls) == 2


def testAgentSubfinder_whenDomainAlreadyProcessed_logsSkipMessage(
    subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    """Unit test to ensure skip logging is executed when domain was already processed."""
    del agent_persist_mock
    subfinder_output = ["subdomain1.co", "subdomain2.co", "subdomain3.co"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)
    logger_info_mock = mocker.patch("agent.subfinder_agent.logger.info")

    subfinder_agent.process(domain_message)

    subfinder_agent.process(domain_message)

    skip_log_calls = [
        call
        for call in logger_info_mock.call_args_list
        if "already been processed" in str(call)
    ]
    assert len(skip_log_calls) == 1


def testUpdateProvidersApiKeys_whenApiKeyIsWhitespaceOnly_skipsProvider(
    subfinder_agent: sub_agent.SubfinderAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Unit test for update_providers_api_keys: when API key is whitespace only, it should be skipped."""
    add_provider_key_mock = mocker.patch.object(
        sub_agent.provider_config_mgr, "add_provider_key"
    )
    args: dict[str, str | None] = {
        "virustotal_api_key": "   ",
        "shodan_api_key": "\t\n",
    }

    subfinder_agent.update_providers_api_keys(args)

    add_provider_key_mock.assert_not_called()


def testAgentSubfinder_whenAppcardsScan_emitsOneSubdomainsMessageOfTheScannedName(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    www_domain_message: message.Message,
) -> None:
    del agent_persist_mock
    subfinder_output = [
        "www.somedomain.com",
        "API.www.somedomain.com",
        "api.www.somedomain.com",
        "blog.www.somedomain.com ",
        "blog.somedomain.com",
    ]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    appcards_subfinder_agent.process(www_domain_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.fingerprint.domain_name.subdomains"
    assert agent_mock[0].data["name"] == "www.somedomain.com"
    assert agent_mock[0].data["subdomains"] == [
        "api.www.somedomain.com",
        "blog.www.somedomain.com",
    ]


def testAgentSubfinder_whenAppcardsScan_looksUpTheScannedName(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    www_domain_message: message.Message,
) -> None:
    del agent_persist_mock, agent_mock
    run_command_mock = mocker.patch("subprocess.run", return_value=None)

    appcards_subfinder_agent.process(www_domain_message)

    subfinder_args = run_command_mock.call_args_list[0].kwargs["args"]
    assert subfinder_args[subfinder_args.index("-d") + 1] == "www.somedomain.com"


def testAgentSubfinder_whenAppcardsScanFindsNamesOutsideTheDomain_dropsThem(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    del agent_persist_mock
    subfinder_output = [
        "somedomain.com",
        "othersomedomain.com",
        "a.other.com",
        "a.somedomain.com",
    ]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    appcards_subfinder_agent.process(domain_message)

    assert agent_mock[0].data["subdomains"] == ["a.somedomain.com"]


def testAgentSubfinder_whenAppcardsScanAndMaxSubdomainsSet_capsTheSortedList(
    appcards_subfinder_agent_max_subdomains: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    del agent_persist_mock
    subfinder_output = ["c.somedomain.com", "b.somedomain.com", "a.somedomain.com"]
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=subfinder_output)

    appcards_subfinder_agent_max_subdomains.process(domain_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].data["subdomains"] == ["a.somedomain.com", "b.somedomain.com"]


def testAgentSubfinder_whenAppcardsScanFindsNothing_emitsTheDomainWithNoSubdomain(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
) -> None:
    del agent_persist_mock
    mocker.patch("agent.subfinder.SubFinder.discover", return_value=[])

    appcards_subfinder_agent.process(domain_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].data == {"name": "somedomain.com"}


def testAgentSubfinder_whenAppcardsScanReceivesTheSameNameAgain_skipsIt(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    www_domain_message: message.Message,
) -> None:
    del agent_persist_mock
    discover_mock = mocker.patch(
        "agent.subfinder.SubFinder.discover", return_value=["a.www.somedomain.com"]
    )

    appcards_subfinder_agent.process(www_domain_message)
    appcards_subfinder_agent.process(www_domain_message)

    assert discover_mock.call_count == 1
    assert len(agent_mock) == 1


def testAgentSubfinder_whenAppcardsScanReceivesASubdomainAndItsDomain_looksUpEach(
    appcards_subfinder_agent: sub_agent.SubfinderAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    domain_message: message.Message,
    www_domain_message: message.Message,
) -> None:
    del agent_persist_mock
    mocker.patch(
        "agent.subfinder.SubFinder.discover",
        return_value=["a.somedomain.com", "a.www.somedomain.com"],
    )

    appcards_subfinder_agent.process(www_domain_message)
    appcards_subfinder_agent.process(domain_message)

    assert [(m.data["name"], m.data["subdomains"]) for m in agent_mock] == [
        ("www.somedomain.com", ["a.www.somedomain.com"]),
        ("somedomain.com", ["a.somedomain.com", "a.www.somedomain.com"]),
    ]
