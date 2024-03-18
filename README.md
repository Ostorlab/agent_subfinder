<h1 align="center">Agent Subfinder</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_subfinder">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Subfinder agent is a subdomain discovery tool that discovers valid subdomains for websites._

<p align="center">
<img src="https://github.com/Ostorlab/agent_subfinder/blob/main/images/logo.png" alt="agent-subfinder" />
</p>

This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for [Subfinder](https://github.com/projectdiscovery/subfinder) discovery tool by by ProjectDiscovery.

## Getting Started
The Subfinder Agent works collectively with other agents. Its job; from a domain name, discover all subdomains in a fast and efficient way, 
and pass its findings to other agents responsible for scanning the subdomains, for example, the [Nuclei agent](https://github.com/Ostorlab/agent_nuclei)


To perform your first scan, simply run the following command:

```shell
oxo scan run --install --agent agent/ostorlab/subfinder --agent agent/ostorlab/nuclei domain-name your-domain.com
```

This command will download and install agents  `agent/ostorlab/subfinder` & `agent/ostorlab/nuclei` and target the domain  `your-domain`.
Nuclei Agent will scan for <your-domain>, and waits for all subdomains found by the Subfinder Agent to performe other scans.
You can use any Agent expecting <v3.asset.domain_name> as an in-selector, like Nmap, OpenVas, etc.

For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Subfinder can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/subfinder
 ```

### Build directly from the repository

 1. To build the Subfinder agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_subfinder.git && cd agent_subfinder
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  oxo scan run --agent agent//subfinder --agent agent//nuclei domain-name your-domain.com
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  oxo scan run --agent agent/[ORGANIZATION]/subfinder --agent agent/[ORGANIZATION]/nuclei  domain-name your-domain.com
      ```


## License
[Apache](./LICENSE)

