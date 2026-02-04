import logging
from rich import logging as rich_logging


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


# PROVIDER_ARG_MAP
# Key   : provider argument name (defined in ostorlab.yaml / oxo.yaml)
# Value : provider name (used for storing the provider in the subfinder provider config)

PROVIDER_ARG_MAP = {
    'virustotal_api_key' : 'virustotal',
}