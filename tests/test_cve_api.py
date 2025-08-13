import json
import os
import pickle
from pathlib import Path
from unittest import mock

import pytest

from cvelib import __version__
from cvelib.cve_api import CveApi, CveRecord, CveRecordValidationError


def test_full_schema_validation():
    with open(Path(__file__).parent / "data/CVEv5_advanced-example.json") as record_file:
        cve_json = json.load(record_file)
    try:
        CveRecord.validate(cve_json, CveRecord.Schemas.V5_SCHEMA)
    except CveRecordValidationError as exc:
        pytest.fail(f"{exc}: {exc.errors}")


def test_container_schema_validation():
    with open(Path(__file__).parent / "data/CVEv5_basic-example.json") as record_file:
        cve_json = json.load(record_file)

    cve_container = CveApi._extract_cna_container(cve_json)
    try:
        CveRecord.validate(cve_container, CveRecord.Schemas.CNA_PUBLISHED)
    except CveRecordValidationError as exc:
        pytest.fail(f"{exc}: {exc.errors}")


def test_invalid_record_schema_validation():
    with pytest.raises(CveRecordValidationError, match="^Schema validation.*failed") as exc_info:
        CveRecord.validate({}, CveRecord.Schemas.CNA_REJECTED)

    # Verify errors are reported in exception message
    assert "'providerMetadata' is a required property" in str(exc_info.value)
    assert "'rejectedReasons' is a required property" in str(exc_info.value)

    # Verify error objects are present in exception object.
    exc_errors = exc_info._excinfo[1].errors
    assert "'providerMetadata' is a required property" in exc_errors[0].message
    assert "'rejectedReasons' is a required property" in exc_errors[1].message


def test_cve_record_validation_error_is_picklable():
    try:
        CveRecord.validate({})
    except CveRecordValidationError as exc:
        assert "'affected' is a required property" in str(exc)
        assert "'affected' is a required property" == exc.errors[0].message
        pickled = pickle.dumps(exc)
        unpickled_exc = pickle.loads(pickled)
        assert "'affected' is a required property" in str(unpickled_exc)
        # Errors do not survive pickling because they include jsonschema-specific objects that
        # are not picklable.
        assert unpickled_exc.errors is None


class TestGeneratorMetadata:
    @pytest.fixture
    def sample_cve_json(self):
        with open(Path(__file__).parent / "data/CVEv5_basic-example.json") as record_file:
            return json.load(record_file)

    def test_add_generator_default(self, sample_cve_json):
        cve_json = sample_cve_json.copy()
        result = CveApi._add_generator(cve_json)
        assert "x_generator" in result
        assert result["x_generator"]["engine"] == f"cvelib {__version__}"

    def test_add_generator_custom(self, sample_cve_json):
        custom_generator = "awesome_cve_cli 1.2.3"
        with mock.patch.dict(os.environ, {"CVE_GENERATOR": custom_generator}):
            cve_json = sample_cve_json.copy()
            result = CveApi._add_generator(cve_json)
            assert "x_generator" in result
            assert result["x_generator"]["engine"] == custom_generator

    def test_generator_not_added(self, sample_cve_json):
        with mock.patch.dict(os.environ, {"CVE_GENERATOR": "-"}):
            cve_json = sample_cve_json.copy()
            result = CveApi._add_generator(cve_json)
            assert "x_generator" not in result

    def test_generator_not_overridden(self, sample_cve_json):
        cve_json = sample_cve_json.copy()
        original_value = {"engine": "cve_cli 9.8.7"}
        cve_json["x_generator"] = original_value

        with mock.patch.dict(os.environ, {"CVE_GENERATOR": "should_not_be_used"}):
            result = CveApi._add_generator(cve_json)
            assert "x_generator" in result
            assert result["x_generator"] == original_value


def test_count_cves():
    with mock.patch("cvelib.cve_api.CveApi._get") as get_mock:
        get_mock.return_value.json.return_value = {"totalCount": 42}
        cve_api = CveApi(username="test_user", org="test_org", api_key="test_key")

        count = cve_api.count_cves()
        get_mock.assert_called_with("cve_count", params={})
        assert count == {"totalCount": 42}

        count = cve_api.count_cves(state="published")
        get_mock.assert_called_with("cve_count", params={"state": "PUBLISHED"})
        assert count == {"totalCount": 42}


def test_transfer():
    with mock.patch("cvelib.cve_api.CveApi._put") as put_mock:
        response = {
            "updated": "CVE-2099-1234",
            "message": "CVE-2099-1234 owning_cna updated",
            "cve_id": "CVE-2099-1234",
            "owning_cna": "new-cna",
            "state": "RESERVED",
            "requested_by": {"cna": "old-cna", "user": "test@example.com"},
            "reserved": "2021-01-14T18:35:17.469Z",
            "time": {"created": "2021-01-14T18:35:17.469Z", "modified": "2021-01-14T18:35:17.469Z"},
        }
        put_mock.return_value.json.return_value = response
        cve_api = CveApi(username="test_user", org="test_org", api_key="test_key")

        result = cve_api.transfer("CVE-2099-1234", "new-cna")
        put_mock.assert_called_with("cve-id/CVE-2099-1234", params={"org": "new-cna"})
        assert result == response
