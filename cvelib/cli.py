import json
import re
import sys
from collections import defaultdict
from datetime import date, datetime
from functools import wraps

import click

from .cve_api import CveApi, CveApiError
from . import __version__

CVE_RE = re.compile(r"^CVE-[12]\d{3}-\d{4,}$")
CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}


def validate_cve(ctx, param, value):
    if value is None:
        return
    if not CVE_RE.match(value):
        raise click.BadParameter("invalid CVE ID.")
    return value


def validate_year(ctx, param, value):
    if value is None:
        return
    # Hopefully this code won't be around in year 10,000.
    if not re.match(r"^[1-9]\d{3}$", value):
        raise click.BadParameter("invalid year.")
    return value


def human_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%c")


def print_cve(cve):
    click.secho(cve["cve_id"], bold=True)
    click.echo(f"├─ State:\t{cve['state']}")
    # CVEs reserved by other CNAs do not include information on who requested them and when.
    if "requested_by" in cve:
        click.echo(f"├─ Owning CNA:\t{cve['owning_cna']}")
        click.echo(f"├─ Reserved by:\t{cve['requested_by']['user']} ({cve['requested_by']['cna']})")
        click.echo(f"└─ Reserved on:\t{human_ts(cve['reserved'])}")
    else:
        click.echo(f"└─ Owning CNA:\t{cve['owning_cna']}")


def print_table(lines):
    """Print tabulated data based on the widths of the longest values in each column."""
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


def print_json_data(data):
    click.echo(json.dumps(data, indent=4, sort_keys=True))


def print_user(user):
    name = get_full_name(user)
    if name:
        click.echo(f"{name} — ", nl=False)
    click.echo(user["username"])
    click.echo(f"├─ Active:\t{bool_to_text(user['active'])}")
    click.echo(f"├─ Roles:\t{', '.join(user['authority']['active_roles']) or 'None'}")

    # Time values are not returned when creating users; secrets (API tokens) are however.
    if "time" in user:
        click.echo(f"├─ Created:\t{human_ts(user['time']['created'])}")
        click.echo(f"└─ Modified:\t{human_ts(user['time']['modified'])}")
    elif "secret" in user:
        click.echo(f"└─ API token:\t{user['secret']}")


def get_full_name(user_data):
    # If no name values are defined on a user, the entire `name` object is not returned in the
    # user data response; see https://github.com/CVEProject/cve-services/issues/436.
    name = user_data.get("name", {})
    if name:
        return f"{name.get('first', '')} {name.get('last', '')}".strip() or None


def bool_to_text(value):
    if value is None:
        return "N/A"
    return "Yes" if value else "No"


def natural_cve_sort(cve):
    if not cve:
        return []
    return [int(x) for x in cve.split("-")[1:]]


def handle_cve_api_error(func):
    """Decorator for catching CVE API exceptions and formatting the error message."""

    @wraps(func)
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except CveApiError as exc:
            error, _, details = str(exc).partition("; returned error: ")
            click.secho("ERROR: ", bold=True, nl=False)
            click.echo(error)
            if details:
                click.secho("DETAILS: ", bold=True, nl=False)
                click.echo(details)
            sys.exit(1)

    return wrapped


class Config:
    def __init__(self, username, org, api_key, env, api_url, interactive):
        self.username = username
        self.org = org
        self.api_key = api_key
        self.env = env
        self.api_url = api_url
        self.interactive = interactive
        self.cve_api = self.init_cve_api()

    def init_cve_api(self):
        return CveApi(
            username=self.username,
            org=self.org,
            api_key=self.api_key,
            env=self.env,
            url=self.api_url,
        )


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-u", "--username", envvar="CVE_USER", required=True, help="Your username (env var: CVE_USER)"
)
@click.option(
    "-o",
    "--org",
    envvar="CVE_ORG",
    required=True,
    help="Your CNA organization short name (env var: CVE_ORG)",
)
@click.option(
    "-a",
    "--api-key",
    envvar="CVE_API_KEY",
    required=True,
    help="Your API key (env var: CVE_API_KEY)",
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
    "--api-url",
    envvar="CVE_API_URL",
    help="Provide arbitrary URL for the CVE API (env var: CVE_API_URL)",
)
@click.option(
    "-i",
    "--interactive",
    envvar="CVE_INTERACTIVE",
    default=False,
    is_flag=True,
    help="Confirm create/update actions before execution (env var: CVE_INTERACTIVE)",
)
@click.version_option(
    __version__, "-V", "--version", prog_name="cvelib", message="%(prog)s %(version)s"
)
@click.pass_context
def cli(ctx, username, org, api_key, env, api_url, interactive):
    """A CLI interface for the CVE Services API."""
    ctx.obj = Config(username, org, api_key, env, api_url, interactive)


@cli.command()
@click.option(
    "-r",
    "--random",
    default=False,
    show_default=True,
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
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.argument("count", default=1, type=click.IntRange(min=1))
@click.pass_context
@handle_cve_api_error
def reserve(ctx, random, year, count, print_raw):
    """Reserve one or more CVE IDs. COUNT is the number of CVEs to reserve; defaults to 1.

    CVE IDs can be reserved one by one (the lowest IDs are reserved first) or in batches of
    multiple IDs per single request. When reserving multiple IDs, you can request those IDs to be
    generated sequentially (default) or non-sequentially (random IDs are selected from your CVE ID
    range).

    For more information, see: "Developer Guide to CVE Services API" (https://git.io/JLcmZ)
    """
    if random and count > 10:
        raise click.BadParameter("requesting non-sequential CVE IDs is limited to 10 per request.")

    if ctx.obj.interactive:
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
        click.echo(" that will be owned by the ", nl=False)
        click.secho(ctx.obj.org, bold=True, nl=False)
        click.echo(" CNA org.")
        if not click.confirm("This operation cannot be reversed; do you want to continue?"):
            click.echo("Exiting...")
            sys.exit(0)
        click.echo()

    cve_api = ctx.obj.cve_api
    cve_data, remaining_quota = cve_api.reserve(count, random, year)
    if print_raw:
        print_json_data(cve_data)
        return

    click.echo("Reserved the following CVE ID(s):\n")
    for cve in cve_data["cve_ids"]:
        print_cve(cve)

    click.echo(f"\nRemaining quota: {remaining_quota}")


@cli.command(name="show")
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.argument("cve_id", callback=validate_cve)
@click.pass_context
@handle_cve_api_error
def show_cve(ctx, print_raw, cve_id):
    """Display a specific CVE ID owned by your CNA."""
    cve_api = ctx.obj.cve_api
    cve = cve_api.show_cve(cve_id=cve_id)
    if print_raw:
        print_json_data(cve)
    else:
        print_cve(cve)


@cli.command(name="list")
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
@click.pass_context
@handle_cve_api_error
def list_cves(ctx, print_raw, sort_by, **query):
    """Filter and list reserved CVE IDs owned by your CNA."""
    cve_api = ctx.obj.cve_api
    cves = list(cve_api.list_cves(**query))
    if print_raw:
        print_json_data(cves)
        return

    if not cves:
        click.echo("No CVEs found...")
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
                human_ts(cve["reserved"]),
            )
        )
    print_table(lines)


@cli.command()
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def quota(ctx, print_raw):
    """Display the available CVE ID quota for your CNA.

    \b
    - "Limit": how many CVE IDs your organization can have in the RESERVED state at once.
    - "Reserved": the number of CVE IDs that are in the RESERVED state across all years.
    - "Available": the number of CVE IDs that can be reserved (that is, "Limit" - "Reserved")
    """
    cve_api = ctx.obj.cve_api
    cve_quota = cve_api.quota()
    if print_raw:
        print_json_data(cve_quota)
        return

    click.echo("CNA quota for ", nl=False)
    click.secho(f"{ctx.obj.org}", bold=True, nl=False)
    click.echo(f":")
    click.echo(f"├─ Limit:\t{cve_quota['id_quota']}")
    click.echo(f"├─ Reserved:\t{cve_quota['total_reserved']}")
    click.echo(f"└─ Available:\t{cve_quota['available']}")


@cli.group(name="user", invoke_without_command=True)
@click.option(
    "-u",
    "--username",
    help="Specify the user to show.",
    show_default="Current user specified in -u/--username/CVE_USER",
)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def show_user(ctx, username, print_raw):
    """Show information about a user."""
    if ctx.invoked_subcommand is not None:
        return

    cve_api = ctx.obj.cve_api
    if not username:
        username = cve_api.username

    user = cve_api.show_user(username)
    if print_raw:
        print_json_data(user)
    else:
        print_user(user)


@show_user.command()
@click.option(
    "-u",
    "--username",
    help="User whose API token should be reset (only ADMIN role users can update other users).",
    show_default="Current user specified in global -u/--username/CVE_USER",
)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def reset_token(ctx, username, print_raw):
    """Reset a user's personal access token (API token).

    This token is used to authenticate each request to the CVE API.
    """
    cve_api = ctx.obj.cve_api
    if not username:
        username = cve_api.username

    api_key = cve_api.reset_api_token(username)
    if print_raw:
        print_json_data(api_key)
        return

    click.echo(f"New API token for ", nl=False)
    click.secho(username, bold=True, nl=False)
    click.echo(":\n")
    click.secho(api_key["API-secret"], bold=True)
    click.echo("\nMake sure to copy your new API token; you won't be able to access it again!")


@show_user.command(name="update")
@click.option(
    "-u",
    "--username",
    help="Username of the user being updated (only ADMIN role users can update other users).",
    show_default="Current user specified in global -u/--username/CVE_USER",
)
@click.option(
    "--mark-active/--mark-inactive", "active", default=None, help="Mark user as active or inactive."
)
@click.option("--new-username", help="Update username.")
@click.option("--name-first", help="Update first name.")
@click.option("--name-last", help="Update last name.")
@click.option("--add-role", help="Add role.", type=click.Choice(CveApi.USER_ROLES))
@click.option("--remove-role", help="Remove role.", type=click.Choice(CveApi.USER_ROLES))
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def update_user(ctx, username, **opts_data):
    """Update a user.

    To reset a user's API token, use `cve user reset-token`.
    """
    print_raw = opts_data.pop("print_raw")
    cve_api = ctx.obj.cve_api
    if not username:
        username = cve_api.username

    user_updates = {}
    for opt, value in opts_data.items():
        if value is not None:
            if opt.startswith("name"):
                opt = opt.replace("_", ".")
            elif opt.endswith("role"):
                opt = "active_roles." + opt.replace("_role", "")
            elif opt == "active":
                # Convert boolean to string since this data is passed as query params
                value = str(value).lower()
            user_updates[opt] = value

    if not user_updates:
        raise click.UsageError("No updates were provided.")

    if ctx.obj.interactive:
        click.echo("You are about to update the ", nl=False)
        click.secho(username, bold=True, nl=False)
        click.echo(" user with the following changes:\n")
        for key, value in user_updates.items():
            click.echo(f"- {key}: ", nl=False)
            click.secho(str(value), bold=True)
        if not click.confirm("\nDo you want to continue?"):
            click.echo("Exiting...")
            sys.exit(0)
        click.echo()

    updated_user = cve_api.update_user(username, **user_updates)
    if print_raw:
        print_json_data(updated_user)
    else:
        click.echo("User updated.")


@show_user.command(name="create")
@click.option("-u", "--username", default="", required=True, help="Set username.")
@click.option("--name-first", default="", help="Set first name.")
@click.option("--name-last", default="", help="Set last name.")
@click.option(
    "--role", "roles", help="Set role.", multiple=True, type=click.Choice(CveApi.USER_ROLES)
)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def create_user(ctx, username, name_first, name_last, roles, print_raw):
    """Create a user in your organization.

    This action is restricted to users with the ADMIN role.

    Note: Once a user is created, they cannot be removed, only marked as inactive. Only create
    users when you really need them.
    """
    user_data = defaultdict(dict)

    if username:
        user_data["username"] = username

    if name_first:
        user_data["name"]["first"] = name_first

    if name_last:
        user_data["name"]["last"] = name_last

    if roles:
        user_data["authority"]["active_roles"] = list(roles)

    if ctx.obj.interactive:
        click.echo("You are about to create the following user under your ", nl=False)
        click.secho(ctx.obj.org, bold=True, nl=False)
        click.echo(f" org:\n\nUsername:\t", nl=False)
        click.secho(username, bold=True)
        click.echo("Full name:\t", nl=False)
        click.secho(name_first + name_last or "None", bold=True)
        click.echo(f"Roles:\t\t", nl=False)
        click.secho(", ".join(roles) or "None", bold=True)
        click.echo("\nThis action cannot be undone; created users can only be marked as inactive.")
        if not click.confirm("Do you want to continue?"):
            click.echo("Exiting...")
            sys.exit(0)
        click.echo()

    cve_api = ctx.obj.cve_api
    created_user = cve_api.create_user(**user_data)["created"]
    if print_raw:
        print_json_data(created_user)
        return

    click.echo("Created user:\n")
    print_user(created_user)
    click.echo("\nMake sure to copy the returned API token; you won't be able to access it again!")


@cli.group(name="org", invoke_without_command=True)
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def show_org(ctx, print_raw):
    """Show information about your organization."""
    if ctx.invoked_subcommand is not None:
        return

    cve_api = ctx.obj.cve_api
    org_data = cve_api.show_org()
    if print_raw:
        print_json_data(org_data)
        return

    click.echo(f"{org_data['name']} — {org_data['short_name']}")
    click.echo(f"├─ Roles:\t{', '.join(org_data['authority']['active_roles']) or 'None'}")
    click.echo(f"├─ Created:\t{human_ts(org_data['time']['created'])}")
    click.echo(f"└─ Modified:\t{human_ts(org_data['time']['modified'])}")


@show_org.command()
@click.option("--raw", "print_raw", default=False, is_flag=True, help="Print response JSON.")
@click.pass_context
@handle_cve_api_error
def users(ctx, print_raw):
    """List all users in your organization."""
    cve_api = ctx.obj.cve_api
    org_users = list(cve_api.list_users())
    if print_raw:
        print_json_data(org_users)
        return

    lines = []
    for user in org_users:
        lines.append(
            (
                user["username"],
                str(get_full_name(user)),
                ", ".join(user["authority"]["active_roles"]) or "None",
                bool_to_text(user["active"]),
                human_ts(user["time"]["created"]),
                human_ts(user["time"]["modified"]),
            )
        )
    lines.sort(key=lambda x: x[0])  # Sort by username
    # Add header after sorting
    lines.insert(0, ("USERNAME", "NAME", "ROLES", "ACTIVE", "CREATED", "MODIFIED"))
    print_table(lines)


@cli.command()
@click.pass_context
def ping(ctx):
    """Ping the CVE Services API to see if it is up."""
    cve_api = ctx.obj.cve_api
    ok, error_msg = cve_api.ping()

    click.echo(f"CVE API Status — {cve_api.url}\n└─ ", nl=False)
    if ok:
        click.secho(f"OK", fg="green")
    else:
        click.secho("ERROR:", bold=True, nl=False)
        click.echo(f" {error_msg}")
