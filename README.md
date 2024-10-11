# cvelib

A library and a command line interface for the CVE Services API.

**Note**: version 1.4.0 of cvelib is compatible with CVE Services 2.3.1 and CVE JSON schema 5.1.0.

## Requirements

- Python version 3.8 or greater
- [pip](https://pypi.org/project/pip/)

## Installation

### Linux, MacOS, Windows

```bash
python3 -m pip install --user cvelib
```

For more information on installing Python packages from PyPI, see the
[Python Packaging User Guide](https://packaging.python.org/tutorials/installing-packages/#installing-from-pypi).

If you are using Windows, `pip` may not add the path to use the `cve` command to your environment.
If it was not added, you will most likely see the error:

```
cve : The term 'cve' is not recognized as the name of a cmdlet, function, script file, or operable program.
Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
```

To resolve this error, add the file path for where your `cve.exe` file resides (for example,
`C:\Users\<username>\AppData\Roaming\Python\Python39\Scripts`) to your `PATH` variable. You can
edit your environment variables by searching *Edit the system environment variables* from the Start menu.

### Podman/Docker

You can fetch a specific version of the `cvelib` library installed in a container image at
https://quay.io/repository/prodsecdev/cvelib. You can set up an alias to run the `cve` command using this container
image:

```bash
alias cve='podman run -it --rm quay.io/prodsecdev/cvelib'
# OR
alias cve='docker run -it --rm quay.io/prodsecdev/cvelib'
```

The `latest` container image tag will always point to the latest available version of the `cvelib` package in PyPI.

## CLI Setup and Configuration

Each CLI command executed requires the user to authenticate to the CVE Services API. You can provide
the authentication details with every command (using options `-u/--username`, `-o/--org`, and
`-a/--api-key`), or set them in the following environment variables:

### Linux & MacOS

```bash
$ export CVE_USER=margo
$ export CVE_ORG=acme
$ export CVE_API_KEY=<api_key>
```

### Windows Command Line

```
C:\> setx CVE_USER margo
C:\> setx CVE_ORG acme
C:\> setx CVE_API_KEY <api_key>
```

### Windows PowerShell

```
PS C:\> $Env:CVE_USER="margo"
PS C:\> $Env:CVE_ORG="acme"
PS C:\> $Env:CVE_API_KEY="api_key"
```

### Podman/Docker

To pass the configuration variables to the `cvelib` container, define them in an `.env` file:

```
CVE_USER=margo
CVE_ORG=acme
CVE_API_KEY=<api_key>
```

Then, specify that file in your Podman/Docker command, for example:

```bash
podman run -it --rm --env-file=.env quay.io/prodsecdev/cvelib ping
```

Alternatively, you can set the environment variables as shown in the sections above and pass them to the container
using:

```bash
podman run -it --rm -e CVE_ORG -e CVE_API_KEY -e CVE_USER quay.io/prodsecdev/cvelib ping
```

### Additional Configuration

Additional options that have an accompanying environment variable include:

* `-e/--environment` or `CVE_ENVIRONMENT`: allows you to configure the deployment environment
  (that is, the URL at which CVE Services is available) to interface with. Allowed values: `prod`,
  `test`, and `dev`. Separate credentials are required for each environment. The `test` and `dev`
  environments may not be consistently available during the development life cycle of CVE Services.

* `--api-url` or `CVE_API_URL`: allows you to override the URL for the CVE Services API that would
  otherwise be determined by the deployment environment you selected. This is useful for local
  testing to point to a CVE Services API instance running on localhost (for example,
  `export CVE_API_URL=http://localhost:3000/api/`).

* `-i/--interactive` or `CVE_INTERACTIVE`: every create/update action will require confirmation
  before a request is sent to CVE Services. Truthy values for the environment variable are:
  `1`, `t`, `yes`.

### Command Autocompletion

Autocompletion of subcommands is supported for the following shells:

#### Bash

Add the following line to your `~/.bashrc` file:

```bash
eval "$(_CVE_COMPLETE=bash_source cve)"
```

#### ZSH

Add the following line to your `~/.zshrc` file:

```bash
eval "$(_CVE_COMPLETE=zsh_source cve)"
```

#### Fish

Add the following line to a `~/.config/fish/completions/cve.fish` file:

```bash
eval (env _CVE_COMPLETE=fish_source cve)
```

## CLI Usage Examples

Available options and commands can be displayed by running `cve --help`. The following are
examples of some commonly used operations.

Reserve one CVE ID in the current year (you will be prompted to confirm your action):

```bash
cve --interactive reserve
```

Reserve three non-sequential CVE IDs for a specific year:

```bash
cve reserve 3 --year 2021 --random
```

Publish a CVE record for an already-reserved CVE ID:

```bash
cve publish CVE-2022-1234 --cve-json '{"affected": [], "descriptions": [], "providerMetadata": {}, "references": []}'
```

For information on the required properties in a given CVE JSON record, see the `cnaPublishedContainer` schema in:
https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json.

List all rejected CVEs for year 2018:

```bash
cve list --year 2018 --state reject
```

Assuming you have the `ADMIN` role (also called an _Org Admin_), create a new user in your
organization with:

```bash
cve user create -u foo@bar.com --name-first Foo --name-last Bar
```

Mark a user as inactive (again, assuming you have the `ADMIN` role):

```bash
cve user update -u foo@bar.com --mark-inactive
```

Reset your own API key:

```bash
cve user reset-key
```

List all users in your organization:

```bash
cve org users
```

See `-h/--help` of any command for a complete list of sub-commands and options.

## Library Usage Example

`cvelib` also exposes a Python interface to CVE Services that can be used within any Python application that includes
`cvelib` as its dependency. The following is an example Python function that fetches a CVE record for a given CVE ID:

```python
import os
from cvelib.cve_api import CveApi

def fetch_cve_record(cve_id: str) -> dict:
    cve_api = CveApi(
        username=os.getenv("CVE_USER"),
        org=os.getenv("CVE_ORG"),
        api_key=os.getenv("CVE_API_KEY"),
    )
    cve = cve_api.show_cve_record(cve_id)
    return cve
```

For more information, see the individual methods defined in the
[`CveApi` interface](https://github.com/RedHatProductSecurity/cvelib/blob/master/cvelib/cve_api.py).

## Other CVE Services Clients

- Client-side library written in JavaScript: https://github.com/xdrr/cve.js
- A web-based client interface and a client library in JavaScript: https://github.com/CERTCC/cveClient
- A web-based tool for creating and editing CVE records in the CVE JSON v5 format:
  https://github.com/Vulnogram/Vulnogram
  - A hosted instance is available at: https://vulnogram.github.io/#editor

## Development Setup

```bash
git clone https://github.com/RedHatProductSecurity/cvelib.git
cd cvelib
python3 -m venv venv  # Must be Python 3.6 or later
source venv/bin/activate
pip install --upgrade pip
pip install -e .
pip install tox
# If you want to use any of the dev dependencies outside of Tox, you can install them all with:
pip install -e .[dev]
```

To enable command autocompletion when using a virtual environment, add the line noted in `Command Autocompletion`
above to your `venv/bin/activate` file, for example:

```bash
echo 'eval "$(_CVE_COMPLETE=bash_source cve)"' >> venv/bin/activate
```

This project uses the [Black](https://black.readthedocs.io) code formatter. To reformat the entire code base after you make any changes, run:

```bash
black .
```

To sort all imports using [ruff](https://docs.astral.sh/ruff/) (which replicates the behavior of
[isort](https://pycqa.github.io/isort/), run:

```bash
ruff check --select I --fix .
```

Running tests and linters:

```bash
# Run all tests and format/lint checks (also run as a Github action)
tox
# Run format check only
tox -e black
# Run tests against Python 3.6 only
tox -e py36
# Run a single test against Python 3.6 only
tox -e py36 -- tests/test_cli.py::test_cve_show
```

Any changes in the commands, their options, or help texts must be reflected in the generated man pages. To refresh
them, run:

```bash
pip install click-man
click-man cve
# OR
tox -e manpages
```

---

[CVE](https://cve.org) is a registered trademark of [The MITRE Corporation](https://www.mitre.org).
