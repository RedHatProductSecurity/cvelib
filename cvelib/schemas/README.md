# CVE JSON Schemas

The `CVE_JSON_5.0_bundled_X.Y.Z.json` schema document in this directory is a copy of the complete schema from
https://github.com/CVEProject/cve-schema.

The container-specific schema documents are individual sub-schemas, extracted from the above schema, that
validate the CNA rejected/published and ADP objects that the CVE Services API accepts in PUT/POST requests. They are
extracted from the full schema using the `extract_container_schemas.py` script in this directory.
