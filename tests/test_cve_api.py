import json
import pickle
from pathlib import Path

import pytest

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
