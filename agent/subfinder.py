"""Wrapper module around the Subfinder subdomaine discovery tool."""
import contextlib
import tempfile
import subprocess
import logging
import os



logger = logging.getLogger(__name__)


class SubFinder:
    """Class responsible for executing & processing output of the Subfinder discovery tool."""
    _output_file = None

    @contextlib.contextmanager
    def subfinder_handler(self):
        self._output_file = tempfile.NamedTemporaryFile(suffix='.txt', prefix='subfinder', dir='/tmp')
        try:
            yield self
        except Exception as e:
            logger.info('Subfinder agent encountered following problem : %s', e)
        finally:
            self._output_file.close()


    def _subdomain_discovery(self, domain: str, output_file) -> None:
        logger.info('starting subdomain discovery for %s', domain)
        command = ['subfinder', '-d', domain, '-o',  output_file.name]

        subprocess.run(command)


    def _parse_output(self, output_file):
        with open(output_file.name, 'r') as f:
            sub_domains = f.read().splitlines()
        return sub_domains

    def discover(self, domain):
        self._subdomain_discovery(domain, self._output_file)
        sub_domains = self._parse_output(self._output_file)
        return sub_domains