# CVE JSON Schemas

The `CVE_JSON_5.0_bundled_5.0.0.json` schema document in this directory is a copy of this file:

https://github.com/CVEProject/cve-schema/blob/v5.0.0/schema/v5.0/docs/CVE_JSON_5.0_bundled.json

The `*_container_5.0.0.json` schema documents are individual sub-schemas, extracted from the above schema, that
validate the CNA rejected/published and ADP objects that the CVE Services API accepts in PUT/POST requests. They are
extracted from the full schema using the `extract_container_schemas.py` script in this directory.
