"""Agent implementation for Subfinder : subdomain discovery tool that discovers valid subdomains for websites."""

import tld
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import subfinder

from agent.config import logger, STORAGE_NAME , PROVIDER_ARG_MAP
from agent.provider_config_manager import ProviderConfigManager


provider_config_manager =  ProviderConfigManager()


class SubfinderAgent(agent.Agent, agent_persist_mixin.AgentPersistMixin):
    """Subfinder agent implementation."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)

        # Update providers configuration with API keys
        providers_arg_names = PROVIDER_ARG_MAP.keys()
        logger.info("Starting update of providers configuration with API keys.")

        for provider_arg_name in providers_arg_names:
            provider_api_key = self.args.get(provider_arg_name)

            if provider_api_key:

                provider_name = PROVIDER_ARG_MAP.get(provider_arg_name)

                logger.info("Adding API key for provider '%s'.", provider_name)
            
                provider_config_manager.add_provider_key(provider_name, provider_api_key)
            else:
                logger.debug("No API key provided for provider '%s'; skipping.", provider_name)

        logger.info("Providers API keys configuration update completed.")


        self._use_all_sources: bool = self.args.get("use_all_sources") or False
        self._active_only: bool = self.args.get("active_only") or False
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
