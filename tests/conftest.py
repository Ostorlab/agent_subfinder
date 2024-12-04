"""Pytest fixtures for the Subfinder agent"""

import random
import json

import pytest
import pathlib

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import subfinder_agent


@pytest.fixture(scope="function", name="subfinder_agent")
def fixture_subfinder_agent():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/subfinder",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = subfinder_agent.SubfinderAgent(definition, settings)
        return agent


@pytest.fixture(scope="function", name="subfinder_agent_max_subdomains")
def fixture_subfinder_agent_max_subdomains():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/subfinder",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="max_subdomains", type="int", value=json.dumps(2).encode()
                )
            ],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = subfinder_agent.SubfinderAgent(definition, settings)
        return agent


@pytest.fixture
def subfinder_definition() -> agent_definitions.AgentDefinition:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args = [
            {
                "name": "virustotal_key",
                "value": "Justrandomvalue",
                "type": "string",
            },
        ]
        return definition


@pytest.fixture
def subfinder_settings() -> runtime_definitions.AgentSettings:
    settings = runtime_definitions.AgentSettings(
        key="agent/ostorlab/subfinder",
        bus_url="NA",
        bus_exchange_topic="NA",
        args=[],
        healthcheck_port=random.randint(5000, 6000),
        redis_url="redis://guest:guest@localhost:6379",
    )
    return settings
