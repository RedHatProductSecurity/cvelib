import json
import re
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from cvelib.cli import cli

DEFAULT_OPTS = ["-o", "test_org", "-u", "test_user", "-a", "test_api_key"]


@mock.patch("cvelib.cli.CveApi.show_cve_id")
@mock.patch("cvelib.cli.CveApi.show_cve_record")
def test_cve_id_show(show_cve_record, show_cve_id):
    show_cve_id.return_value = {
        "cve_id": "CVE-2099-1000",
        "cve_year": "2099",
        "owning_cna": "acme",
        "requested_by": {"cna": "acme", "user": "jack@example.com"},
        "reserved": "2021-01-14T18:35:17.928Z",
        "state": "RESERVED",
        "time": {"created": "2021-01-14T18:35:17.469Z", "modified": "2021-01-14T18:35:17.929Z"},
    }

    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000"])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "CVE-2099-1000\n"
        "├─ State:\tRESERVED\n"
        "├─ Owning CNA:\tacme\n"
        "├─ Reserved by:\tjack@example.com (acme)\n"
        "├─ Reserved on:\tThu Jan 14 18:35:17 2021 +0000\n"
        "└─ Updated on:\tThu Jan 14 18:35:17 2021 +0000\n"
    )
    assert not show_cve_record.called


@mock.patch("cvelib.cli.CveApi.show_cve_id")
@mock.patch("cvelib.cli.CveApi.show_cve_record")
def test_reserved_not_owned_cve_id(show_cve_record, show_cve_id):
    show_cve_id.return_value = {
        "cve_id": "CVE-2099-0001",
        "cve_year": "2099",
        "owning_cna": "[REDACTED]",
        "state": "RESERVED",
    }

    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-0001"])
    assert result.exit_code == 0, result.output
    assert result.output == "CVE-2099-0001\n├─ State:\tRESERVED\n└─ Owning CNA:\t[REDACTED]\n"
    assert not show_cve_record.called


@mock.patch("cvelib.cli.CveApi.show_cve_id")
@mock.patch("cvelib.cli.CveApi.show_cve_record")
def test_published_not_owned_cve_id(show_cve_record, show_cve_id):
    show_cve_id.return_value = {
        "cve_id": "CVE-2099-0001",
        "cve_year": "2099",
        "owning_cna": "acme",
        "dateUpdated": "2000-02-08T17:22:07.669Z",
        "state": "PUBLISHED",
    }

    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-0001"])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "CVE-2099-0001\n"
        "├─ State:\tPUBLISHED\n"
        "├─ Owning CNA:\tacme\n"
        "└─ Updated on:\tTue Feb  8 17:22:07 2000 +0000\n"
    )
    assert not show_cve_record.called


@mock.patch("cvelib.cli.CveApi.show_cve_id")
@mock.patch("cvelib.cli.CveApi.show_cve_record")
def test_cve_show_full(show_cve_record, show_cve_id):
    show_cve_id.return_value = {
        "cve_id": "CVE-2099-1000",
        "cve_year": "2099",
        "owning_cna": "acme",
        "requested_by": {"cna": "acme", "user": "jack@example.com"},
        "reserved": "2021-01-14T18:35:17.928Z",
        "state": "RESERVED",
        "time": {"created": "2021-01-14T18:35:17.469Z", "modified": "2021-01-14T18:35:17.929Z"},
    }
    show_cve_record.return_value = {
        "containers": {
            "cna": {
                "providerMetadata": {
                    "dateUpdated": "2022-09-27T15:29:12.964Z",
                    "orgId": "65fe0718-9a55-4e29-8e61-d4ddf6d83e28",
                    "shortName": "acme",
                },
                "rejectedReasons": [{"lang": "en", "value": "text"}],
            }
        },
        "cveMetadata": {
            "assignerOrgId": "65fe0718-9a55-4e29-8e61-d4ddf6d83e28",
            "assignerShortName": "acme",
            "cveId": "CVE-2099-1000",
            "dateRejected": "2022-09-27T15:26:42.117Z",
            "dateReserved": "2021-01-14T18:35:17.469Z",
            "dateUpdated": "2022-09-27T15:29:12.964Z",
            "state": "REJECTED",
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
    }

    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000", "--show-record"])
    assert result.exit_code == 0, result.output
    printed_cve_id, _, printed_cve_record = result.output.partition("-----")
    assert printed_cve_id == (
        "CVE-2099-1000\n"
        "├─ State:\tRESERVED\n"
        "├─ Owning CNA:\tacme\n"
        "├─ Reserved by:\tjack@example.com (acme)\n"
        "├─ Reserved on:\tThu Jan 14 18:35:17 2021 +0000\n"
        "└─ Updated on:\tThu Jan 14 18:35:17 2021 +0000\n"
    )
    # Don't bother checking the data since we provide it as a fixture anyway. Simply check that a
    # JSON is displayed and the length of the printed string is something reasonable.
    assert printed_cve_record.startswith("\n{")
    assert len(printed_cve_record) > 100


@mock.patch("cvelib.cli.CveApi.show_cve_id")
@mock.patch("cvelib.cli.CveApi.show_cve_record")
def test_cve_show_adp(show_cve_record, show_cve_id):
    show_cve_id.return_value = {
        "cve_id": "CVE-2099-1000",
        "cve_year": "2099",
        "owning_cna": "acme",
        "requested_by": {"cna": "acme", "user": "jack@example.com"},
        "reserved": "2021-01-14T18:35:17.928Z",
        "state": "PUBLISHED",
        "time": {"created": "2021-01-14T18:35:17.469Z", "modified": "2021-01-14T18:35:17.929Z"},
    }
    show_cve_record.return_value = {
        "containers": {
            "cna": {
                "providerMetadata": {
                    "dateUpdated": "2022-09-27T15:29:12.964Z",
                    "orgId": "65fe0718-9a55-4e29-8e61-d4ddf6d83e28",
                    "shortName": "acme",
                },
                "references": [{"url": "https://example.com"}],
            },
            "adp": [
                {
                    "providerMetadata": {
                        "dateUpdated": "2022-09-27T15:29:12.964Z",
                        "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                        "shortName": "alice-corp",
                    },
                    "references": [{"url": "https://example.com/alice"}],
                },
                {
                    "providerMetadata": {
                        "dateUpdated": "2022-09-27T15:29:12.964Z",
                        "orgId": "87654321-9a55-4e29-8e61-d4ddf6d83e28",
                        "shortName": "bob-corp",
                    },
                    "references": [{"url": "https://example.com/bob"}],
                },
            ],
        },
        "cveMetadata": {
            "assignerOrgId": "65fe0718-9a55-4e29-8e61-d4ddf6d83e28",
            "assignerShortName": "acme",
            "cveId": "CVE-2099-1000",
            "dateRejected": "2022-09-27T15:26:42.117Z",
            "dateReserved": "2021-01-14T18:35:17.469Z",
            "dateUpdated": "2022-09-27T15:29:12.964Z",
            "state": "PUBLISHED",
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
    }

    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000", "--show-adp"])
    assert result.exit_code == 0, result.output
    _, _, printed_cve_record = result.output.partition("-----")
    # Don't bother checking the data since we provide it as a fixture anyway. Simply check that both
    # ADP containers are present.
    assert "alice-corp ADP data:" in printed_cve_record
    assert "bob-corp ADP data:" in printed_cve_record

    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000", "--show-adp", "bob-corp"])
    assert result.exit_code == 0, result.output
    _, _, printed_cve_record = result.output.partition("-----")
    assert "alice-corp ADP data:" not in printed_cve_record
    assert "bob-corp ADP data:" in printed_cve_record

    result = runner.invoke(cli, DEFAULT_OPTS + ["show", "CVE-2099-1000", "--show-adp", "random"])
    assert result.exit_code == 0, result.output
    _, _, printed_cve_record = result.output.partition("-----")
    assert printed_cve_record.strip() == "CVE record does not contain ADP data from org(s): random."


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
            "state": "PUBLISHED",
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
            "state": "REJECTED",
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
            "CVE ID          STATE       OWNING CNA   RESERVED BY   RESERVED ON\n"
            "CVE-2021-3001   RESERVED    acme         bob (acme)    "
            "Thu Jan 14 18:32:19 2021 +0000\n"
            "CVE-2021-3002   PUBLISHED   acme         ann (acme)    "
            "Thu Jan 14 18:32:57 2021 +0000\n"
            "CVE-2021-3003   REJECTED    acme         eve (corp)    "
            "Thu Jan 14 18:34:50 2021 +0000\n"
        )
        result = runner.invoke(cli, DEFAULT_OPTS + ["list", "--no-header"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "CVE-2021-3001   RESERVED    acme   bob (acme)   Thu Jan 14 18:32:19 2021 +0000\n"
            "CVE-2021-3002   PUBLISHED   acme   ann (acme)   Thu Jan 14 18:32:57 2021 +0000\n"
            "CVE-2021-3003   REJECTED    acme   eve (corp)   Thu Jan 14 18:34:50 2021 +0000\n"
        )


def test_count():
    count_response = {"totalCount": 123}
    with mock.patch("cvelib.cli.CveApi.count_cves") as count_cves:
        count_cves.return_value = count_response

        # No state filter
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["count"])
        assert result.exit_code == 0, result.output
        assert result.output == "Total CVE records: 123\n"
        count_cves.assert_called_with(state=None)

        # With state filter
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["count", "--state", "published"])
        assert result.exit_code == 0, result.output
        assert result.output == "Total CVE records in PUBLISHED state: 123\n"
        count_cves.assert_called_with(state="PUBLISHED")

        # Raw output
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["count", "--raw"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == count_response


class TestCvePublish:
    cve_id = "CVE-2001-0635"
    cna_dict = {
        "affected": [
            {
                "cpes": ["cpe:/o:redhat:linux:7.1"],
                "defaultStatus": "affected",
                "product": "Red Hat Linux",
                "vendor": "Red Hat",
            }
        ],
        "descriptions": [
            {
                "lang": "en",
                "value": "There would be words here if this was real data.",
            }
        ],
        "providerMetadata": {
            "orgId": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "shortName": "test_org",
        },
        "references": [
            {
                "name": cve_id,
                "url": f"https://access.redhat.com/security/cve/{cve_id}",
            },
            {
                "name": f"bz#1616605: {cve_id} security flaw",
                "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1616605",
            },
        ],
    }
    cve_response_data = {
        "containers": {"cna": cna_dict},
        "cveMetadata": {
            "assignerOrgId": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "assignerShortName": "test_org",
            "cveId": cve_id,
            "datePublished": "2022-05-02T00:00:00Z",
            "dateUpdated": "2021-06-29T12:33:52.892Z",
            "dateReserved": "2021-06-29T12:33:52.892Z",
            "requesterUserId": "cb55b254-cf8f-46f6-bfbf-fc1d71ba439a",
            "state": "PUBLISHED",
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
    }

    @mock.patch("cvelib.cli.CveApi.publish")
    @mock.patch("cvelib.cli.CveApi.update_published")
    def test_cve_publish(self, update_published, publish):
        cna_text = json.dumps(self.cna_dict)
        response_dict = {
            "created": self.cve_response_data,
            "message": f"{self.cve_id} record was successfully created.",
        }
        publish.return_value = response_dict

        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["publish", self.cve_id, "--cve-json", cna_text])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "Published the following CVE:\n"
            "\n"
            f"{self.cve_id}\n"
            "├─ State:\tPUBLISHED\n"
            "├─ Owning CNA:\ttest_org\n"
            "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
            "└─ Updated on:\tTue Jun 29 12:33:52 2021 +0000\n"
            f"\nAPI response: {self.cve_id} record was successfully created.\n"
        )
        assert not update_published.called

    @mock.patch("cvelib.cli.CveApi.publish")
    @mock.patch("cvelib.cli.CveApi.update_published")
    def test_cve_publish_from_file(self, update_published, publish, tmp_path):
        with open(tmp_path / "cve.json", "w+") as cve_json_file:
            cve_json_file.write(json.dumps(self.cna_dict))

        response_dict = {
            "created": self.cve_response_data,
            "message": f"{self.cve_id} record was " f"successfully created.",
        }
        publish.return_value = response_dict

        runner = CliRunner()
        result = runner.invoke(
            cli, DEFAULT_OPTS + ["publish", self.cve_id, "--cve-json-file", cve_json_file.name]
        )
        assert result.exit_code == 0, result.output
        assert result.output == (
            "Published the following CVE:\n"
            "\n"
            f"{self.cve_id}\n"
            "├─ State:\tPUBLISHED\n"
            "├─ Owning CNA:\ttest_org\n"
            "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
            "└─ Updated on:\tTue Jun 29 12:33:52 2021 +0000\n"
            f"\nAPI response: {self.cve_id} record was successfully created.\n"
        )
        assert not update_published.called


@mock.patch("cvelib.cli.CveApi.publish_adp")
def test_adp_publish(publish_adp):
    adp_text = json.dumps({"references": [{"url": "https://example.com/hello"}]})
    response_dict = {
        "updated": {
            "cveMetadata": {
                "assignerOrgId": "uuid",
                "assignerShortName": "test_org",
                "cveId": "CVE-2001-0635",
                "datePublished": "2022-05-02T00:00:00Z",
                "dateUpdated": "2021-06-29T12:33:52.892Z",
                "dateReserved": "2021-06-29T12:33:52.892Z",
                "state": "PUBLISHED",
            }
        },
        # Omit the rest of the API response message since it may change in the future.
        "message": "CVE-2001-0635 record had a replacement ADP container...",
    }
    publish_adp.return_value = response_dict

    runner = CliRunner()
    result = runner.invoke(
        cli, DEFAULT_OPTS + ["publish-adp", "CVE-2001-0635", "--adp-json", adp_text]
    )
    assert result.exit_code == 0, result.output
    assert result.output == (
        "Published an ADP container for:\n"
        "\n"
        "CVE-2001-0635\n"
        "├─ State:\tPUBLISHED\n"
        "├─ Owning CNA:\ttest_org\n"
        "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
        "└─ Updated on:\tTue Jun 29 12:33:52 2021 +0000\n"
        "\nAPI response: CVE-2001-0635 record had a replacement ADP container...\n"
    )


@mock.patch("cvelib.cli.CveApi.reject")
@mock.patch("cvelib.cli.CveApi.update_rejected")
@mock.patch("cvelib.cli.CveApi.move_to_rejected")
def test_cve_reject_with_record(move_to_rejected, update_rejected, reject):
    cve_id = "CVE-2001-0635"
    cna_dict = {
        "providerMetadata": {
            "orgId": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "shortName": "test_org",
        },
        "rejectedReasons": [
            {
                "lang": "en",
                "value": "There would be words here if this was real data.",
            },
        ],
    }

    cve_dict = {
        "containers": {"cna": cna_dict},
        "cveMetadata": {
            "assignerOrgId": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "assignerShortName": "test_org",
            "cveId": cve_id,
            "dateRejected": "2022-05-02T00:00:00Z",
            "dateUpdated": "2022-05-02T00:00:00Z",
            "dateReserved": "2021-06-29T12:33:52.892Z",
            "requesterUserId": "cb55b254-cf8f-46f6-bfbf-fc1d71ba439a",
            "state": "REJECTED",
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
    }
    cna_text = json.dumps(cna_dict)
    response_dict = {"created": cve_dict, "message": f"{cve_id} record was successfully created."}

    reject.return_value = response_dict
    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["reject", cve_id, "--cve-json", cna_text])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "Rejected the following CVE:\n"
        "\n"
        f"{cve_id}\n"
        "├─ State:\tREJECTED\n"
        "├─ Owning CNA:\ttest_org\n"
        "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
        "└─ Updated on:\tMon May  2 00:00:00 2022 +0000\n"
        f"\nAPI response: {cve_id} record was successfully created.\n"
    )
    assert not update_rejected.called
    assert not move_to_rejected.called


@mock.patch("cvelib.cli.CveApi.reject")
@mock.patch("cvelib.cli.CveApi.update_rejected")
@mock.patch("cvelib.cli.CveApi.move_to_rejected")
def test_cve_reject_without_record(move_to_rejected, update_rejected, reject):
    cve_id = "CVE-2099-1000"
    reject_response = {
        "updated": {
            "cve_id": "CVE-2099-1000",
            "cve_year": "2099",
            "owning_cna": "acme",
            "requested_by": {"cna": "acme", "user": "jack@example.com"},
            "reserved": "2021-06-29T12:33:52.892Z",
            "state": "REJECTED",
            "time": {"created": "2021-06-29T12:33:52.892Z", "modified": "2021-06-29T12:33:52.892Z"},
        },
        "message": f"{cve_id} record was successfully updated.",
    }

    move_to_rejected.return_value = reject_response
    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["reject", cve_id])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "Rejected the following CVE:\n"
        "\n"
        f"{cve_id}\n"
        "├─ State:\tREJECTED\n"
        "├─ Owning CNA:\tacme\n"
        "├─ Reserved by:\tjack@example.com (acme)\n"
        "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
        "└─ Updated on:\tTue Jun 29 12:33:52 2021 +0000\n"
    )
    assert not update_rejected.called
    assert not reject.called


@mock.patch("cvelib.cli.CveApi.move_to_reserved")
def test_cve_undo_reject(move_to_reserved):
    cve_id = "CVE-2099-1000"
    reserved_response = {
        "updated": {
            "cve_id": "CVE-2099-1000",
            "cve_year": "2099",
            "owning_cna": "acme",
            "requested_by": {"cna": "acme", "user": "jack@example.com"},
            "reserved": "2021-06-29T12:33:52.892Z",
            "state": "RESERVED",
            "time": {"created": "2021-06-29T12:33:52.892Z", "modified": "2021-06-29T12:33:52.892Z"},
        },
        "message": f"{cve_id} record was successfully updated.",
    }

    move_to_reserved.return_value = reserved_response
    runner = CliRunner()
    result = runner.invoke(cli, DEFAULT_OPTS + ["undo-reject", cve_id])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "Moved the following CVE to reserved:\n"
        "\n"
        f"{cve_id}\n"
        "├─ State:\tRESERVED\n"
        "├─ Owning CNA:\tacme\n"
        "├─ Reserved by:\tjack@example.com (acme)\n"
        "├─ Reserved on:\tTue Jun 29 12:33:52 2021 +0000\n"
        "└─ Updated on:\tTue Jun 29 12:33:52 2021 +0000\n"
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
        ],
        "meta": {
            "remaining_quota": 10,
        },
    }
    with mock.patch("cvelib.cli.CveApi.reserve") as reserve:
        reserve.return_value = reserved_cves
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
            "└─ Reserved on:\tMon May 24 18:14:34 2021 +0000\n"
            "CVE-2021-20002\n"
            "├─ State:\tRESERVED\n"
            "├─ Owning CNA:\ttest_org\n"
            "├─ Reserved by:\ttest_user@test_org.com (test_org)\n"
            "└─ Reserved on:\tMon May 24 18:14:34 2021 +0000\n"
            "\n"
            "Remaining quota: 10\n"
        )


def test_active_user_show():
    user_data = {
        "UUID": "ac821fed-cbfa-47ab-bcde-822d759c7902",
        "active": True,
        "authority": {"active_roles": ["ADMIN"]},
        "name": {
            "first": "Test",
            "last": "User",
        },
        "org_UUID": "304d44d8-3dd1-475d-83c1-5cbefb92b780",
        "time": {"created": "2021-04-22T02:09:08.823Z", "modified": "2021-04-22T02:09:08.823Z"},
        "username": "test@user",
    }
    with mock.patch("cvelib.cli.CveApi.show_user") as show_user:
        show_user.return_value = user_data
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["user"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "Test User — test@user\n"
            "├─ Active:\tYes\n"
            "├─ Roles:\tADMIN\n"
            "├─ Created:\tThu Apr 22 02:09:08 2021 +0000\n"
            "└─ Modified:\tThu Apr 22 02:09:08 2021 +0000\n"
        )


def test_inactive_user_show():
    user_data = {
        "UUID": "ac821fed-cbfa-47ab-bcde-822d759c7902",
        "active": False,
        "authority": {"active_roles": []},
        "name": {
            "first": "",
            "last": "",
        },
        "org_UUID": "304d44d8-3dd1-475d-83c1-5cbefb92b780",
        "time": {"created": "2021-04-22T02:09:08.823Z", "modified": "2021-04-22T02:09:08.823Z"},
        "username": "test@user",
    }
    with mock.patch("cvelib.cli.CveApi.show_user") as show_user:
        show_user.return_value = user_data
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["user"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "test@user\n"
            "├─ Active:\tNo\n"
            "├─ Roles:\tNone\n"
            "├─ Created:\tThu Apr 22 02:09:08 2021 +0000\n"
            "└─ Modified:\tThu Apr 22 02:09:08 2021 +0000\n"
        )


def test_reset_key():
    api_key = {"API-secret": "foo-key"}
    with mock.patch("cvelib.cli.CveApi.reset_api_key") as reset_api_key:
        reset_api_key.return_value = api_key
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["user", "reset-key", "-u", "test_user"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "New API key for test_user:\n\n"
            "foo-key\n\n"
            "Make sure to copy your new API key; you won't be able to access it again!\n"
        )


def test_user_list():
    users = [
        {
            "UUID": "fe12571e-4a47-4272-9cc4-c61802c05356",
            "active": True,
            "authority": {"active_roles": ["ADMIN"]},
            "name": {"first": "Hello", "last": "World"},
            "org_UUID": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "time": {"created": "2021-05-26T19:27:44.567Z", "modified": "2021-05-26T19:28:52.766Z"},
            "username": "hello@world",
        },
        {
            "UUID": "cb55b254-cf8f-46f6-bfbf-fc1d71ba439a",
            "active": False,
            "authority": {"active_roles": []},
            "name": {"first": "Foo"},
            "org_UUID": "19f229d4-f3d5-4605-bf93-521fa4499c06",
            "time": {"created": "2021-05-26T19:27:24.366Z", "modified": "2021-05-26T19:32:57.857Z"},
            "username": "foo",
        },
    ]
    with mock.patch("cvelib.cli.CveApi.list_users") as list_users:
        list_users.return_value = users
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["org", "users"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "USERNAME      NAME          ROLES   ACTIVE   CREATED                          "
            "MODIFIED\n"
            "foo           Foo           None    No       Wed May 26 19:27:24 2021 +0000   "
            "Wed May 26 19:32:57 2021 +0000\n"
            "hello@world   Hello World   ADMIN   Yes      Wed May 26 19:27:44 2021 +0000   "
            "Wed May 26 19:28:52 2021 +0000\n"
        )


def test_show_org():
    org = {
        "UUID": "19f229d4-f3d5-4605-bf93-521fa4499c06",
        "authority": {"active_roles": ["CNA"]},
        "name": "Test Org",
        "policies": {"id_quota": 1000},
        "short_name": "test_org",
        "time": {"created": "2021-04-21T02:09:07.389Z", "modified": "2021-04-21T02:09:07.389Z"},
    }
    with mock.patch("cvelib.cli.CveApi.show_org") as show_org:
        show_org.return_value = org
        runner = CliRunner()
        result = runner.invoke(cli, DEFAULT_OPTS + ["org"])
        assert result.exit_code == 0, result.output
        assert result.output == (
            "Test Org — test_org\n"
            "├─ Roles:\tCNA\n"
            "├─ Created:\tWed Apr 21 02:09:07 2021 +0000\n"
            "└─ Modified:\tWed Apr 21 02:09:07 2021 +0000\n"
        )


def test_validate_good():
    runner = CliRunner()
    example_cve_file = str(Path(__file__).parent / "data/CVEv5_basic-example.json")
    result = runner.invoke(
        cli, ["validate", "--cve-json-file", example_cve_file, "--schema-type", "full"]
    )
    assert result.exit_code == 0, result.output
    assert result.output == "CVE record is valid!\n"


def test_validate_bad():
    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--cve-json", '{"bad": "record"}'])
    assert result.exit_code == 1
    assert re.search("^Schema validation .* failed:\n", result.output)


def test_exit_on_help():
    with mock.patch("cvelib.cli.CveApi.show_org") as show_org:
        show_org.return_value = {}
        runner = CliRunner()
        result = runner.invoke(cli, ["org", "--help"])
        assert result.exit_code == 0, result.output
        # The command is named after the function that is called.
        assert result.output.startswith("Usage: cli org")
