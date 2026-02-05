"""Agent implementation for Subfinder : subdomain discovery tool that discovers valid subdomains for websites."""

import logging

import tld
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import config as agent_config
from agent import provider_config_manager
from agent import subfinder

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)

logger = logging.getLogger(__name__)

provider_config_mgr = provider_config_manager.ProviderConfigManager()


class SubfinderAgent(agent.Agent, agent_persist_mixin.AgentPersistMixin):
    """Subfinder agent implementation."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)

        self.update_providers_api_keys(self.args)

        self._use_all_sources: bool = self.args.get("use_all_sources") or False
        self._active_only: bool = self.args.get("active_only") or False
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def update_providers_api_keys(self, args: dict[str, str | None]) -> None:
        """Updates providers configuration with API keys from arguments."""

        logger.info("Starting update of providers configuration with API keys.")

        for arg, value in args.items():
            if value is None or arg not in agent_config.PROVIDER_ARG_MAP:
                continue

            provider_api_key = value

            if provider_api_key.strip() == "":
                logger.debug(
                    "No API key provided for provider argument '%s'; skipping.",
                    arg,
                )
                continue

            provider_name = agent_config.PROVIDER_ARG_MAP.get(arg)

            logger.info("Adding API key for provider '%s'.", provider_name)

            provider_config_mgr.add_provider_key(
                provider_name,
                provider_api_key,
            )

        logger.info("Providers API keys configuration update completed.")

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

        if self.set_add(agent_config.STORAGE_NAME, canonalized_domain) is True:
            with subfinder.SubFinder(
                use_all_sources=self._use_all_sources, active_only=self._active_only
            ) as subfinder_handler:
                sub_domains = subfinder_handler.discover(domain_name)

                if self.args.get("max_subdomains") is not None:
                    sub_domains = sub_domains[: self.args.get("max_subdomains")]

                for sub in sub_domains:
                    logger.info("Found subdomain: %s", sub)
                    self.emit(selector="v3.asset.domain_name", data={"name": sub})

        else:
            logger.info("%s has already been processed. skipping for now.", domain_name)


if __name__ == "__main__":
    logger.info("starting agent ...")
    SubfinderAgent.main()
