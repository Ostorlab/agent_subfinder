"""Unittests for the Subfinder Agent."""

from ostorlab.agent import message


def testAgentSubfinder_whenFindsSubDomains_emitsBackFindings(subfinder_agent, agent_mock, agent_persist_mock, mocker):
    """Unittest for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = [
        'subdomain1.co',
        'subdomain2.co',
        'subdomain3.co'
    ]

    mocker.patch('agent.subfinder.SubFinder.discover', return_value=subfinder_output)

    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'somedomain.com'})
    subfinder_agent.process(msg)

    assert len(agent_mock) == 3
    assert agent_mock[0].selector =='v3.asset.domain_name',  agent_mock[0].data['name'] == 'subdomain1'


def testAgentSubfinder_whenDomainHasAlreadyBeenProcessed_theDomainIsSkipped(subfinder_agent,
                                                                            agent_persist_mock,
                                                                            agent_mock,
                                                                            mocker):
    """Unittest for Agent Subfinder. When it receives a domain that has already been processed,
    the agent should skip it."""
    del agent_persist_mock
    subfinder_output = [
        'subdomain1.co',
        'subdomain2.co',
        'subdomain3.co'
    ]
    mocker.patch('agent.subfinder.SubFinder.discover', return_value=subfinder_output)
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'somedomain.com'})

    subfinder_agent.process(msg)
    subfinder_agent.process(msg)

    assert len(agent_mock) == 3

def testAgentSubfinder_withInvalidTLD_doNotRaiseAnException(subfinder_agent, agent_persist_mock, agent_mock):
    """Unittest for Agent Subfinder, when the TLD is invalid, the agent exists without raising an exception."""
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'somedomain.invalidtld'})

    subfinder_agent.process(msg)

    assert len(agent_mock) == 0


def testAgentSubfinder_whenMaxSubDomainsSet_emitsBackFindings(subfinder_agent_max_subdomains, agent_mock,
                                                              agent_persist_mock, mocker):
    """Unittest for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = [
        'subdomain1.co',
        'subdomain2.co',
        'subdomain3.co'
    ]

    mocker.patch('agent.subfinder.SubFinder.discover', return_value=subfinder_output)

    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'somedomain.com'})
    subfinder_agent_max_subdomains.process(msg)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector =='v3.asset.domain_name',  agent_mock[0].data['name'] == 'subdomain1'
