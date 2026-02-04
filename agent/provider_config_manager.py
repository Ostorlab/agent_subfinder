from agent.config import logger, CONFIG_PATH

import ruamel.yaml
import pathlib


class ProviderConfigManager:

    """
    Manages API keys for providers in the Subfinder configuration file.
    """

    def __init__(self, config_path: str = CONFIG_PATH):
        self.config_path = config_path

    def add_provider_key(self, provider_name: str, api_key : str) -> None:
        """
        Add an API key for a specific provider.
        """

        if not provider_name:
            logger.error("Provider name cannot be empty.")
            return
        if not api_key:
            logger.error("API key cannot be empty for provider '%s'.", provider_name)
            return
            
        self.__save_provider_key(provider_name, api_key)
        

    def __save_provider_key(self, provider_name: str, api_key: str) -> None:
        """
        Save an API key for a given provider in the Subfinder configuration file.

        Args:
            provider_name (str): The provider name (e.g., 'virustotal', 'fofa').
            api_key (str): The API key to add.
        """
        yaml = ruamel.yaml.YAML(typ="safe")
        yaml.default_flow_style = False  # Ensure block-style lists

        config_path = pathlib.Path(self.config_path)

        if not config_path.exists():
            logger.error("Configuration file not found at %s.", config_path)
            return

        try:
            config = yaml.load(config_path.read_text()) or {}
        except ruamel.yaml.YAMLError as e:
            logger.error("Failed to parse configuration file: %s", e)
            return

        if provider_name in config:
            if api_key not in config[provider_name]:
                config[provider_name].append(api_key)
                logger.info("Added API key for provider '%s'.", provider_name)
            else:
                logger.info("API key for provider '%s' already exists; skipping.", provider_name)
        else:
            config[provider_name] = [api_key]
            logger.info("Created new provider entry '%s' with API key.", provider_name)

        try:
            with config_path.open("w") as file:
                yaml.dump(config, file)
        except (IOError, OSError) as write_error:
            logger.error("Failed to write configuration file: %s", write_error)
