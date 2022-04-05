"""Agent implementation for Subfinder : subdomain discovery tool that discovers valid subdomains for websites."""
import logging

from rich import logging as rich_logging
from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import subfinder


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)


class SubfinderAgent(agent.Agent, agent_persist_mixin.AgentPersistMixin):
    """Subfinder agent implementation."""
    def __init__(self,
                agent_definition: agent_definitions.AgentDefinition,
                agent_settings: runtime_definitions.AgentSettings) -> None:

        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        """Process messages of type  v3.asset.domain_name
        Runs Subfinder on the domain name and emits back the findings.

        Args:
            message: The received message.
        """
        logger.info('processing message of selector : %s', message.selector)
        domain_name = message.data['name']

        if self.set_is_member('processed_domains', domain_name) is False:
            self.set_add('processed_domains', domain_name)

            with subfinder.SubFinder().subfinder_handler() as subfinder_handler:
                sub_domains = subfinder_handler.discover(domain_name)

                for sub in sub_domains:
                    self.set_add('processed_domains', sub)
                    self.emit(selector='v3.asset.domain_name', data={'name': sub})

        else:
            logger.info('%s has already been processed. skipping for now.', domain_name)


if __name__ == '__main__':
    logger.info('starting agent ...')
    SubfinderAgent.main()
