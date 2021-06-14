# cvelib

A library and a command line interface for the CVE Services API.

## Requirements

- Python version 3.6 or greater
- pip

## Installation

Universal Installation that should work on Linux, MacOS and Windows.

```
pip install --user cvelib
```

For more information on installing Python packages from PyPI, see the [Python Packaging User Guide](https://packaging.python.org/tutorials/installing-packages/#installing-from-pypi).

## CLI Setup and Configuration

Each CLI command executed requires the user to authenticate to the CVE Services API. You can provide
the authentication details with every command (using options `-u/--username`, `-o/--org`, and
`-a/--api-key`), or set them in the following environment variables:

### Linux & MacOS

```
export CVE_USER=margo
export CVE_ORG=acme
export CVE_API_KEY=<api_key>
```

### Windows

```
set CVE_USER=margo
set CVE_ORG=acme
set CVE_API_KEY=<api_key>
```

Additional options that have an accompanying environment variable include:

* `-e/--environment` or `CVE_ENVIRONMENT`: allows you to configure the deployment environment
  (that is, the URL at which the service is available) to interface with. Allowed values: `prod`,
  `dev`.

* `--api-url` or `CVE_API_URL`: allows you to override the URL for the CVE API that would
  otherwise be determined by the deployment environment you selected. This is useful for local
  testing to point to a CVE API instance running on localhost.

* `-i/--interactive` or `CVE_INTERACTIVE`: every create/update action will require confirmation
  before a request is sent. 

## CLI Usage

Available options and commands can be displayed by running `cve --help`. The following are
examples of some commonly used operations.

Reserve one CVE ID in the current year (you will be prompted to confirm your action):

```
cve --interactive reserve
```

Reserve three non-sequential CVE IDs for a specific year:

```
cve reserve 3 --year 2021 --random
```

List all rejected CVEs for year 2018:

```
cve list --year 2018 --state reject
```

Assuming you have the `ADMIN` role (also called an _Org Admin_), create a new user in your
organization with:

```
cve user create -u foo@bar.com --name-first Foo --name-last Bar
```

Mark a user as inactive (again, assuming you have the `ADMIN` role):

```
cve user update -u foo@bar.com --mark-inactive
```

Reset your own API token:

```
cve user reset-token
```

List all users in your organization:

```
cve org users
```

See `-h/--help` of any command for a complete list of sub-commands and options.

## Development Setup

```bash
git clone https://github.com/RedHatProductSecurity/cvelib.git
cd cvelib
python3 -m venv venv  # Must be Python 3.6 or later
source venv/bin/activate
pip install --upgrade pip
pip install -e .
pip install tox
```

This project uses the [Black](https://black.readthedocs.io) code formatter. To reformat the entire
code base after you make any changes, run:

```bash
# Reformat code base with Black
pip install black
black .
```

Running tests:

```bash
# Run all tests and format check (also run as a Github action)
tox
# Run format check only
tox -e black
# Run tests against Python 3.6 only
tox -e py36
# Run a single test against Python 3.6 only
tox -e py36 -- tests/test_cli.py::test_cve_show
```

---

[CVE](https://cve.mitre.org/) is a trademark of [The MITRE Corporation](https://www.mitre.org/).
