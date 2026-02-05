"""Manages provider API keys in the Subfinder YAML configuration file."""

import logging
import pathlib

import ruamel.yaml

from agent import config

logger = logging.getLogger(__name__)

CONFIG_PATH = config.CONFIG_PATH
PROVIDER_ARG_MAP = config.PROVIDER_ARG_MAP


class ProviderConfigManager:
    """Manages API keys for providers in the Subfinder YAML configuration file."""

    def __init__(self, config_path: str = CONFIG_PATH):
        self._config_path = config_path

    def add_provider_key(self, provider_name: str, api_key: str) -> None:
        """Adds an API key for a specific provider."""
        if provider_name is None or provider_name.strip() == "":
            logger.error("Provider name cannot be empty.")
            return
        if api_key is None or api_key.strip() == "":
            logger.error("API key cannot be empty for provider '%s'.", provider_name)
            return

        self._save_provider_key(provider_name, api_key)

    def _save_provider_key(self, provider_name: str, api_key: str) -> None:
        """Saves an API key for a given provider in the Subfinder config file."""
        yaml = ruamel.yaml.YAML(typ="safe")
        yaml.default_flow_style = False

        config_path = pathlib.Path(self._config_path)

        if config_path.exists() is False:
            logger.error("Configuration file not found at %s.", config_path)
            return

        try:
            loaded_config = yaml.load(config_path.read_text())
            config = loaded_config if loaded_config is not None else {}
        except ruamel.yaml.YAMLError as e:
            logger.error("Failed to parse configuration file: %s", e)
            return

        if provider_name in config:
            if api_key not in config[provider_name]:
                config[provider_name].append(api_key)
                logger.info("Added API key for provider '%s'.", provider_name)
            else:
                logger.info(
                    "API key for provider '%s' already exists; skipping.", provider_name
                )
        else:
            config[provider_name] = [api_key]
            logger.info("Created new provider entry '%s' with API key.", provider_name)

        try:
            with config_path.open("w") as file:
                yaml.dump(config, file)
        except (IOError, OSError) as write_error:
            logger.error("Failed to write configuration file: %s", write_error)
