# cvelib

A library and a command line interface for the CVE Services API.

## Requirements

- Python version 3.6 or greater
- [pip](https://pypi.org/project/pip/)

## Installation

Universal installation method that works on Linux, MacOS, and Windows:

```
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
edit your environment variables by searching *Edit the system environment variables*.

## CLI Setup and Configuration

Each CLI command executed requires the user to authenticate to the CVE Services API. You can provide
the authentication details with every command (using options `-u/--username`, `-o/--org`, and
`-a/--api-key`), or set them in the following environment variables:

### Linux & MacOS

```
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

Publish a CVE record for an already-reserved CVE ID:

```
cve publish 'CVE-2022-1234' --json '{"affected": [], "descriptions": [], "providerMetadata": {}, "references": []}'
```

For information on the required properties in a given CVE JSON record, see the `cnaPublishedContainer` schema in:
https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json.

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

Reset your own API key:

```
cve user reset-key
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

[CVE](https://cve.org) is a registered trademark of [The MITRE Corporation](https://www.mitre.org).
