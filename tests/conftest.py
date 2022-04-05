"""Pytest fixtures for the Subfinder agent"""

import pytest
from agent import subfinder_agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

@pytest.fixture(scope='function', name='subfinder_agent')
def  fixture_subfinder_agent():
    definitions = agent_definitions.AgentDefinition(
        name='subfinder',
        in_selectors=['v3.asset.domain_name'],
        out_selectors=['v3.asset.domain_name']
    )
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/subfinder',
        bus_url='NA',
        bus_exchange_topic='NA',
        bus_management_url='http://guest:guest@localhost:15672/',
        bus_vhost='/',
        redis_url='redis://guest:guest@localhost:6379'
    )
    agent = subfinder_agent.SubfinderAgent(agent_definition=definitions, agent_settings= settings)
    return agent
