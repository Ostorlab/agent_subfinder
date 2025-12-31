"""Agent implementation for Subfinder : subdomain discovery tool that discovers valid subdomains for websites."""

import logging
import pathlib

import ruamel.yaml
from rich import logging as rich_logging
import tld
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

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
CONFIG_PATH = "/root/.config/subfinder/provider-config.yaml"


def set_virustotal_api_key(
    virustotal_key: str,
    config_path: str = CONFIG_PATH,
) -> None:
    """Update the Subfinder provider configuration file with the VirusTotal API key."""
    yaml = ruamel.yaml.YAML(typ="safe")
    yaml.default_flow_style = False  # Ensure block-style lists
    config_path = pathlib.Path(config_path)

    if config_path.exists() is False:
        logger.error("Configuration file not found at %s.", config_path)
        return None

    config = yaml.load(config_path.read_text()) or {}

    if "virustotal" in config:
        if virustotal_key not in config["virustotal"]:
            config["virustotal"].append(virustotal_key)
    else:
        config["virustotal"] = [virustotal_key]

    try:
        with config_path.open("w") as file:
            yaml.dump(config, file)
    except (IOError, OSError) as write_error:
        logger.error("Failed to write configuration file: %s", write_error)


class SubfinderAgent(agent.Agent, agent_persist_mixin.AgentPersistMixin):
    """Subfinder agent implementation."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)

        virustotal_key = self.args.get("virustotal_api_key")
        if virustotal_key is not None:
            logger.info("Updating configuration with VirusTotal API key.")
            set_virustotal_api_key(virustotal_key)
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
