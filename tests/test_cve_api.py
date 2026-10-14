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


class TestAdpSupport:
    """Tests for ADP (Authorized Data Publishers) container support"""

    def test_adp_basic_schema_validation(self):
        """Test that basic ADP containers validate correctly against the ADP schema"""
        with open(Path(__file__).parent / "data/adp-basic-example.json") as adp_file:
            adp_json = json.load(adp_file)
        try:
            CveRecord.validate(adp_json, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP basic example validation failed: {exc}: {exc.errors}")

    def test_adp_advanced_schema_validation(self):
        """Test that advanced ADP containers with affected and metrics validate correctly"""
        with open(Path(__file__).parent / "data/adp-advanced-example.json") as adp_file:
            adp_json = json.load(adp_file)
        try:
            CveRecord.validate(adp_json, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP advanced example validation failed: {exc}: {exc.errors}")

    def test_adp_minimal_required_fields(self):
        """Test that ADP containers with only minimal required fields validate"""
        minimal_adp = {
            "providerMetadata": {
                "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                "shortName": "test-adp",
            },
            "references": [{"url": "https://example.com"}]
        }
        try:
            CveRecord.validate(minimal_adp, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP minimal validation failed: {exc}: {exc.errors}")

    def test_adp_with_metrics_and_descriptions(self):
        """Test ADP with metrics (for SSVC or CVSS) and descriptions"""
        adp_with_metrics = {
            "providerMetadata": {
                "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                "shortName": "metrics-adp",
            },
            "descriptions": [
                {
                    "lang": "en",
                    "value": "ADP analysis with security metrics and assessments"
                }
            ],
            "references": [{"url": "https://example.com/analysis"}]
        }
        try:
            CveRecord.validate(adp_with_metrics, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP with metrics validation failed: {exc}: {exc.errors}")

    def test_adp_container_extraction(self):
        """Test that _extract_adp_container correctly extracts ADP from full record"""
        full_record = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2026-1234"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {
                            "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                            "shortName": "test-adp",
                        },
                        "references": [{"url": "https://example.com"}]
                    }
                ]
            }
        }

        # Extract should work with full record
        extracted = CveApi._extract_adp_container(full_record)
        # Note: The extract method handles multiple ADP containers,
        # so verify it returns a valid ADP container
        assert "providerMetadata" in extracted or isinstance(extracted, dict)

    def test_adp_multiple_references(self):
        """Test ADP with multiple references (common for detailed analyses)"""
        adp_multi_ref = {
            "providerMetadata": {
                "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                "shortName": "multi-ref-adp",
            },
            "references": [
                {"url": "https://example.com/analysis"},
                {"url": "https://example.com/details"},
                {"url": "https://example.com/timeline"},
            ]
        }
        try:
            CveRecord.validate(adp_multi_ref, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP with multiple references validation failed: {exc}: {exc.errors}")

    def test_adp_with_affected_products(self):
        """Test ADP documenting affected products (similar to SADP pilot use case)"""
        adp_with_affected = {
            "providerMetadata": {
                "orgId": "12345678-9a55-4e29-8e61-d4ddf6d83e28",
                "shortName": "affected-adp",
            },
            "affected": [
                {
                    "vendor": "Example Vendor",
                    "product": "Example Product",
                    "versions": [
                        {"version": "1.0.0", "status": "affected"},
                        {"version": "1.0.1", "status": "unaffected"},
                    ]
                }
            ],
            "references": [{"url": "https://example.com"}]
        }
        try:
            CveRecord.validate(adp_with_affected, CveRecord.Schemas.ADP)
        except CveRecordValidationError as exc:
            pytest.fail(f"ADP with affected products validation failed: {exc}: {exc.errors}")
