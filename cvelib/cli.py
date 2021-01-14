import json
import re
import sys
from datetime import date, datetime
from functools import wraps

import click

from .idr import Idr, IdrException

CVE_RE = re.compile(r"^CVE-[12]\d{3}-\d{4,}$")
CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "show_default": True,
    "max_content_width": 100,
}


def validate_cve(ctx, param, value):
    if value is None:
        return
    if not CVE_RE.match(value):
        raise click.BadParameter("invalid CVE ID")
    return value


def validate_year(ctx, param, value):
    if value is None:
        return
    # Hopefully this code won't be around in year 10,000.
    if not re.match(r"^[1-9]\d{3}$", value):
        raise click.BadParameter("invalid year")
    return value


def print_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%c")


def print_cve(cve):
    click.secho(cve["cve_id"], bold=True)
    click.echo(f"├─ State:\t{cve['state']}")
    click.echo(f"├─ Owning CNA:\t{cve['owning_cna']}")
    click.echo(f"├─ Reserved by:\t{cve['requested_by']['user']} ({cve['requested_by']['cna']})")
    click.echo(f"└─ Reserved on:\t{cve['reserved']}")


def natural_cve_sort(cve):
    if not cve:
        return []
    return [int(x) for x in cve.split("-")[1:]]


def handle_idr_exc(func):
    """Decorator for catching IDR exceptions and formatting the error message."""

    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IdrException as exc:
            error, _, details = str(exc).partition('; returned error: ')
            click.secho('ERROR: ', bold=True, nl=False)
            click.echo(error)
            if details:
                click.secho('DETAILS: ', bold=True, nl=False)
                click.echo(details)
            sys.exit(1)

    return wrapped


class Config:
    def __init__(self, username, org, api_key, env, idr_url, interactive):
        self.username = username
        self.org = org
        self.api_key = api_key
        self.env = env
        self.idr_url = idr_url
        self.interactive = interactive

    def init_idr(self, **kwargs):
        return Idr(
            username=self.username,
            org=self.org,
            api_key=self.api_key,
            env=self.env,
            url=self.idr_url,
            **kwargs,
        )


pass_config = click.make_pass_decorator(Config)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-u", "--username", envvar="CVE_USER", required=True, help="User name (env var: CVE_USER)"
)
@click.option(
    "-o",
    "--org",
    envvar="CVE_ORG",
    required=True,
    help="CNA organization short name (env var: CVE_ORG)",
)
@click.option(
    "-a", "--api-key", envvar="CVE_API_KEY", required=True, help="API key (env var: CVE_API_KEY)"
)
@click.option(
    "-e",
    "--env",
    envvar="CVE_ENVIRONMENT",
    default="prod",
    type=click.Choice(["prod", "dev"]),
    help="Select deployment environment to query (env var: CVE_ENVIRONMENT)",
)
@click.option(
    "--idr-url",
    envvar="CVE_IDR_URL",
    help="Provide arbitrary URL for the IDR service (env var: CVE_IDR_URL)",
)
@click.option(
    "-i",
    "--interactive",
    envvar="CVE_INTERACTIVE",
    default=False,
    is_flag=True,
    help="Confirm create/update actions before execution (env var: CVE_INTERACTIVE)",
)
@click.pass_context
def cli(ctx, username, org, api_key, env, idr_url, interactive):
    """A CLI interface for the CVE Project services."""
    ctx.obj = Config(username, org, api_key, env, idr_url, interactive)


@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-r",
    "--random",
    default=False,
    is_flag=True,
    help="Reserve multiple CVE IDs non-sequentially.",
)
@click.option(
    "-y",
    "--year",
    default=lambda: str(date.today().year),
    callback=validate_year,
    help="Reserve CVE ID(s) for a given year.",
    show_default="current year",
)
@click.option(
    "-c",
    "--owning-cna",
    callback=validate_year,
    help="Specify the CNA that should own the reserved CVE ID(s)",
    show_default="CNA org specified in -o/--org/CVE_ORG",
)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.argument("count", default=1, type=click.IntRange(min=1))
@pass_config
@handle_idr_exc
def reserve(ctx, random, year, owning_cna, count, print_raw):
    """Reserve one or more CVE IDs.

    CVE IDs can be reserved one by one (the lowest IDs are reserved first) or in batches of
    multiple IDs per single request. When reserving multiple IDs, you can request those IDs to be
    generated sequentially or non-sequentially.

    For more information, see: "Developer Guide to CVE Services API" (https://git.io/JLcmZ)
    """
    if random and count > 10:
        raise click.BadParameter("requesting non-sequential CVE IDs is limited to 10 per request")

    if not owning_cna:
        owning_cna = ctx.org

    if ctx.interactive:
        click.echo("You are about to reserve ", nl=False)
        if count > 1:
            click.secho(
                f"{count} {'non-sequential' if random else 'sequential'} ", bold=True, nl=False
            )
            click.echo("CVE IDs for year ", nl=False)
        else:
            click.secho("1 ", bold=True, nl=False)
            click.echo("CVE ID for year ", nl=False)
        click.secho(year, bold=True, nl=False)
        click.echo(' that will be owned by the ', nl=False)
        click.secho(owning_cna, bold=True, nl=False)
        click.echo(' CNA org.')
        if not click.confirm("This operation cannot be reversed; do you want to continue?"):
            click.echo("Exiting...")
            sys.exit(0)

    idr = ctx.init_idr()
    response = idr.reserve(count, random, year, owning_cna)
    cve_data = response.json()

    if print_raw:
        click.echo(json.dumps(cve_data, indent=4, sort_keys=True))
    else:
        click.echo("Reserved the following CVE ID(s):\n")
        for cve in cve_data["cve_ids"]:
            print_cve(cve)

        click.echo(f"\nRemaining quota: {response.headers['CVE-API-REMAINING-QUOTA']}")


@cli.command(name="show", context_settings=CONTEXT_SETTINGS)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.argument("cve_id", callback=validate_cve)
@pass_config
@handle_idr_exc
def show_cve(ctx, print_raw, cve_id):
    """Display a specific CVE ID owned by your CNA."""
    idr = ctx.init_idr()
    response = idr.show_cve(cve_id=cve_id)
    cve = response.json()

    if print_raw:
        click.echo(json.dumps(cve, indent=4, sort_keys=True))
    else:
        print_cve(cve)


@cli.command(name="list", context_settings=CONTEXT_SETTINGS)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.option(
    "--sort-by",
    type=click.Choice(["cve_id", "state", "user", "reserved"], case_sensitive=False),
    default="cve_id",
    help="Sort output.",
)
@click.option("--year", callback=validate_year, help="Filter by year.")
@click.option(
    "--state",
    type=click.Choice(["reserved", "public", "reject"], case_sensitive=False),
    help="Filter by reservation state.",
)
@click.option(
    "--reserved-lt", type=click.DateTime(), help="Filter by reservation time before timestamp."
)
@click.option(
    "--reserved-gt", type=click.DateTime(), help="Filter by reservation time after timestamp."
)
@pass_config
@handle_idr_exc
def list_cves(ctx, print_raw, sort_by, **query):
    """Filter and list CVE IDs owned by your CNA."""
    idr = ctx.init_idr()
    response = idr.list_cves(**query)
    cve_data = response.json()

    if print_raw:
        click.echo(json.dumps(cve_data, indent=4, sort_keys=True))
        return

    cves = cve_data["cve_ids"]
    if not cves:
        click.echo('No CVEs found...')
        return

    if sort_by:
        key = sort_by.lower()
        if key == "user":
            cves.sort(key=lambda x: x["requested_by"]["user"])
        elif key == "cve_id":
            cves.sort(key=lambda x: natural_cve_sort(x["cve_id"]))
        elif key == "reserved_asc":
            cves.sort(key=lambda x: x["reserved"])
        elif key == "state":
            cves.sort(key=lambda x: x["state"])

    lines = [("CVE ID", "STATE", "OWNING CNA", "REQUESTED BY", "RESERVED")]
    for cve in cves:
        lines.append(
            (
                cve["cve_id"],
                cve["state"],
                cve["owning_cna"],
                f"{cve['requested_by']['user']} ({cve['requested_by']['cna']})",
                print_ts(cve["reserved"]),
            )
        )
    col_widths = []
    for item_index in range(len(lines[0])):
        max_len_value = max(lines, key=lambda x: len(x[item_index]))
        col_widths.append(len(max_len_value[item_index]))

    for idx, line in enumerate(lines):
        text = "".join(f"{value:<{width + 3}}" for value, width in zip(line, col_widths)).strip()
        if idx == 0:
            click.secho(text, bold=True)
        else:
            click.echo(text)


@cli.command(context_settings=CONTEXT_SETTINGS)
@pass_config
@handle_idr_exc
def quota(ctx):
    """Display the available CVE ID quota for your CNA.

    \b
    - "Limit": how many CVE IDs your organization can have in the RESERVED state at once.
    - "Reserved": the number of CVE IDs that are in the RESERVED state across all years.
    - "Available": the number of CVE IDs that can be reserved (that is "Limit" - "Available")
    """
    idr = ctx.init_idr()
    response = idr.quota()
    idr_quota = response.json()

    click.echo("CNA quota for ", nl=False)
    click.secho(f"{ctx.org}", bold=True, nl=False)
    click.echo(f":")
    click.echo(f"├─ Limit:\t{idr_quota['id_quota']}")
    click.echo(f"├─ Reserved:\t{idr_quota['total_reserved']}")
    click.echo(f"└─ Available:\t{idr_quota['available']}")


@cli.command(context_settings=CONTEXT_SETTINGS)
@pass_config
@handle_idr_exc
def ping(ctx):
    """Ping the IDR service to see if it is up."""
    idr = ctx.init_idr(raise_exc=False)
    idr_status = idr.ping()

    click.echo("IDR API Status: ", nl=False)
    if idr_status.ok:
        click.secho("OK", fg="green")
    else:
        click.secho(f"NOT OK ({idr_status.status_code})", fg="red")
    click.echo(f"└─ {idr.url}")
