from unittest import mock

from click.testing import CliRunner

from cvelib.cli import cli

DEFAULT_OPTS = ["-o", "test_org", "-u", "test_user", "-a", "test_api_key"]


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
    with mock.patch("cvelib.cli.CveApi.show_cve") as show_cve:
        show_cve.return_value = cve
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "CVE-2099-1000\n"
            "├─ State:\tRESERVED\n"
            "├─ Owning CNA:\tacme\n"
            "├─ Reserved by:\tjack@example.com (acme)\n"
            "└─ Reserved on:\tThu Jan 14 18:35:17 2021\n"
        )


def test_cve_list():
    cves = [
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
    with mock.patch("cvelib.cli.CveApi.list_cves") as list_cves:
        list_cves.return_value = cves
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["list"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "CVE ID          STATE      OWNING CNA   REQUESTED BY   RESERVED\n"
            "CVE-2021-3001   RESERVED   acme         bob (acme)     Thu Jan 14 18:32:19 2021\n"
            "CVE-2021-3002   PUBLIC     acme         ann (acme)     Thu Jan 14 18:32:57 2021\n"
            "CVE-2021-3003   REJECT     acme         eve (corp)     Thu Jan 14 18:34:50 2021\n"
        )


def test_quota():
    quota = {"id_quota": 100, "total_reserved": 10, "available": 90}
    with mock.patch("cvelib.cli.CveApi.quota") as get_quota:
        get_quota.return_value = quota
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["quota"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "CNA quota for test_org:\n"
            "├─ Limit:\t100\n"
            "├─ Reserved:\t10\n"
            "└─ Available:\t90\n"
        )


def test_reserve():
    reserved_cves = {
        "cve_ids": [
            {
                "requested_by": {"cna": "test_org", "user": "test_user@test_org.com"},
                "cve_id": "CVE-2021-20001",
                "cve_year": "2021",
                "state": "RESERVED",
                "owning_cna": "test_org",
                "reserved": "2021-05-24T18:14:34.987Z",
            },
            {
                "requested_by": {"cna": "test_org", "user": "test_user@test_org.com"},
                "cve_id": "CVE-2021-20002",
                "cve_year": "2021",
                "state": "RESERVED",
                "owning_cna": "test_org",
                "reserved": "2021-05-24T18:14:34.988Z",
            },
        ]
    }
    with mock.patch("cvelib.cli.CveApi.reserve") as reserve:
        reserve.return_value = reserved_cves, 10
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["reserve", "-y", "2021", "2"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "Reserved the following CVE ID(s):\n"
            "\n"
            "CVE-2021-20001\n"
            "├─ State:\tRESERVED\n"
            "├─ Owning CNA:\ttest_org\n"
            "├─ Reserved by:\ttest_user@test_org.com (test_org)\n"
            "└─ Reserved on:\tMon May 24 18:14:34 2021\n"
            "CVE-2021-20002\n"
            "├─ State:\tRESERVED\n"
            "├─ Owning CNA:\ttest_org\n"
            "├─ Reserved by:\ttest_user@test_org.com (test_org)\n"
            "└─ Reserved on:\tMon May 24 18:14:34 2021\n"
            "\n"
            "Remaining quota: 10\n"
        )
