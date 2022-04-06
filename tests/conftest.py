"""Pytest fixtures for the Subfinder agent"""

import pytest
import pathlib

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import subfinder_agent

@pytest.fixture(scope='function', name='subfinder_agent')
def  fixture_subfinder_agent():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/subfinder',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[],
            healthcheck_port=5301,
            redis_url='redis://guest:guest@localhost:6379')

        agent = subfinder_agent.SubfinderAgent(definition, settings) 
        return agent
