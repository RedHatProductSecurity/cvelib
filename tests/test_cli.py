from unittest import mock

from click.testing import CliRunner

from cvelib.cli import cli

DEFAULT_OPTS = ["-o test", "-u test", "-a test"]


def test_cve_show():
    cve = {
        "cve_id": "CVE-2099-1000",
        "cve_year": "2099",
        "owning_cna": "acme",
        "requested_by": {"cna": "acme", "user": "jack@example.com"},
        "reserved": "2021-01-14T18:35:17.928Z",
        "state": "RESERVED",
        "time": {"created": "2021-01-14T18:35:17.469Z", "modified": "2021-01-14T18:35:17.929Z"},
    }
    with mock.patch("cvelib.cli.Idr.show_cve") as show_cve:
        show_cve.return_value.json.return_value = cve
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000"])
        assert result.exit_code == 0
        assert result.output == (
            "CVE-2099-1000\n"
            "├─ State:\tRESERVED\n"
            "├─ Owning CNA:\tacme\n"
            "├─ Reserved by:\tjack@example.com (acme)\n"
            "└─ Reserved on:\t2021-01-14T18:35:17.928Z\n"
        )


def test_cve_list():
    cves = {
        "cve_ids": [
            {
                "cve_id": "CVE-2021-3001",
                "cve_year": "2021",
                "owning_cna": "acme",
                "requested_by": {"cna": "acme", "user": "bob"},
                "reserved": "2021-01-14T18:32:19.405Z",
                "state": "RESERVED",
                "time": {
                    "created": "2021-01-14T18:32:19.409Z",
                    "modified": "2021-01-14T18:32:19.409Z",
                },
            },
            {
                "cve_id": "CVE-2021-3002",
                "cve_year": "2021",
                "owning_cna": "acme",
                "requested_by": {"cna": "acme", "user": "ann"},
                "reserved": "2021-01-14T18:32:57.955Z",
                "state": "PUBLIC",
                "time": {
                    "created": "2021-01-14T18:32:57.956Z",
                    "modified": "2021-01-14T18:32:57.956Z",
                },
            },
            {
                "cve_id": "CVE-2021-3003",
                "cve_year": "2021",
                "owning_cna": "acme",
                "requested_by": {"cna": "corp", "user": "eve"},
                "reserved": "2021-01-14T18:34:50.916Z",
                "state": "REJECT",
                "time": {
                    "created": "2021-01-14T18:34:50.917Z",
                    "modified": "2021-01-14T18:34:50.917Z",
                },
            },
        ]
    }
    with mock.patch("cvelib.cli.Idr.list_cves") as list_cves:
        list_cves.return_value.json.return_value = cves
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["list"])
        assert result.exit_code == 0
        assert result.output == (
            "CVE ID          STATE      OWNING CNA   REQUESTED BY   RESERVED\n"
            "CVE-2021-3001   RESERVED   acme         bob (acme)     Thu Jan 14 18:32:19 2021\n"
            "CVE-2021-3002   PUBLIC     acme         ann (acme)     Thu Jan 14 18:32:57 2021\n"
            "CVE-2021-3003   REJECT     acme         eve (corp)     Thu Jan 14 18:34:50 2021\n"
        )
