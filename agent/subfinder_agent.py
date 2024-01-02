"""Agent implementation for Subfinder : subdomain discovery tool that discovers valid subdomains for websites."""
import logging

from rich import logging as rich_logging
import tld
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
import validators

from agent import subfinder


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)
STORAGE_NAME = "agent_subfinder_storage"


class SubfinderAgent(agent.Agent, agent_persist_mixin.AgentPersistMixin):
    """Subfinder agent implementation."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        """Process messages of type  v3.asset.domain_name
        Runs Subfinder on the domain name and emits back the findings.

        Args:
            message: The received message.
        """
        logger.info("processing message of selector : %s", message.selector)
        domain_name = message.data["name"]
        canonalized_domain = tld.get_tld(
            domain_name, as_object=True, fix_protocol=True, fail_silently=True
        )
        if canonalized_domain is None:
            return

        canonalized_domain = canonalized_domain.fld

        if self.set_add(STORAGE_NAME, canonalized_domain) is True:
            with subfinder.SubFinder() as subfinder_handler:
                sub_domains = subfinder_handler.discover(domain_name)

                if self.args.get("max_subdomains") is not None:
                    sub_domains = sub_domains[: self.args.get("max_subdomains")]

                for sub in sub_domains:
                    try:
                        if validators.domain(sub) is True:
                            self.emit(
                                selector="v3.asset.domain_name", data={"name": sub}
                            )
                    except validators.ValidationError:
                        logger.warning("Got an invalid subdomain: %s", sub)

        else:
            logger.info("%s has already been processed. skipping for now.", domain_name)


if __name__ == "__main__":
    logger.info("starting agent ...")
    SubfinderAgent.main()
