"""Wrapper module around the Subfinder subdomaine discovery tool."""
import contextlib
import tempfile
import subprocess
import logging
from typing import List


logger = logging.getLogger(__name__)


class Error(Exception):
    """Custom Error"""


class SubFinderError(Error):
    """SubFinder Error"""


class SubFinder:
    """Class responsible for executing & processing output of the Subfinder discovery tool."""
    _output_file = None

    @contextlib.contextmanager
    def subfinder_handler(self):
        """Context manager responsible for handling the output file of the subfinder tool."""
        self._output_file = tempfile.NamedTemporaryFile(suffix='.txt', prefix='subfinder', dir='/tmp')
        try:
            yield self
        except SubFinderError() as e:
            logger.info('Subfinder agent encountered following problem : %s', e)
        finally:
            self._output_file.close()


    def _subdomain_discovery(self, domain: str, output_file: tempfile.NamedTemporaryFile) -> None:
        """Runs the subfinder command."""
        logger.info('starting subdomain discovery for %s', domain)
        command = ['subfinder', '-d', domain, '-o',  output_file.name]

        subprocess.run(command, check=True)


    def _parse_output(self, output_file: tempfile.NamedTemporaryFile) -> List[str]:
        """Reads the output of the subfinder tool, & returns a list of subdomains."""
        with open(output_file.name, 'r', encoding='utf-8') as f:
            sub_domains = f.read().splitlines()
        return sub_domains

    def discover(self, domain: str) -> List[str]:
        """find subdomains for a domain with subfinder tool.

        Args:
            domain to be processed.

        Return:
            list of the subdomains
        """
        self._subdomain_discovery(domain, self._output_file)
        sub_domains = self._parse_output(self._output_file)
        return sub_domains
