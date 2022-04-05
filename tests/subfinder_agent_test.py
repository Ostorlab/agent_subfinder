"""Unittests for the Subfinder Agent."""

from ostorlab.agent import message


def testAgentSubfinder_whenFindsSubDomains_emitsBackFindings(subfinder_agent, agent_mock, agent_persist_mock, mocker):
    """Unittest for emitting back the found subdomains of the agent Subfinder."""
    del agent_persist_mock
    subfinder_output = [
        'subdomain1',
        'subdomain2',
        'subdomain3'
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
    """Unittest for Agent Subfinder. Case where a domain has already been processed, should be skipped."""
    del agent_persist_mock
    subfinder_output = [
        'subdomain1',
        'subdomain2',
        'subdomain3'
    ]
    mocker.patch('agent.subfinder.SubFinder.discover', return_value=subfinder_output)
    msg = message.Message.from_data(selector='v3.asset.domain_name', data={'name': 'somedomain.com'})

    subfinder_agent.process(msg)
    subfinder_agent.process(msg)

    assert len(agent_mock) == 3
