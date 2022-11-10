import copy
import json
import sys
from pathlib import Path

SCHEMAS_DIR = Path(__file__).parent


def load_full_schema():
    try:
        schema_file = next(SCHEMAS_DIR.glob("CVE_JSON_5.0_bundled_*.json"))
    except StopIteration:
        print("ERROR: No schema file found in the schemas directory!")
        sys.exit(1)
    with open(schema_file) as f:
        data = json.load(f)

    version = str(schema_file).rpartition("_")[2].removesuffix(".json")
    return data, version


def create_sub_schema(schema, container, file_name):
    # Pair down definitions to only those used by the properties defined in the container
    definitions_to_include = set(extract_refs(container["properties"]))

    # Recursively identify all "$ref"s used in the definitions we got in the previous step,
    # and loop until we inspect each of definitions to see if they refer to any other definitions.
    refs = set(definitions_to_include)
    while True:
        refs = set(extract_refs({k: v for k, v in schema["definitions"].items() if k in refs}))
        new_refs = refs - definitions_to_include
        if not new_refs:
            break
        definitions_to_include.update(refs)

    # Build final schema from the container as the top level objects, and the definitions that
    # all of its properties require.
    container_schema = {
        "definitions": {
            k: v for k, v in schema["definitions"].items() if k in definitions_to_include
        }
    }
    container_schema = {
        **container_schema,
        **container,
        "$schema": schema["$schema"],
        "title": file_name.removesuffix(".json"),
    }

    with open(SCHEMAS_DIR / file_name, "w+") as f:
        json.dump(container_schema, f, indent=2, sort_keys=True)


def extract_refs(data, ref_name="$ref"):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == ref_name:
                yield value.split("/")[2]
            else:
                yield from extract_refs(value, ref_name)
    elif isinstance(data, list):
        for item in data:
            yield from extract_refs(item, ref_name)


if __name__ == "__main__":
    full_schema, schema_version = load_full_schema()

    # Remove global attributes that don't apply to the sub-schemas
    for attr in ("$id", "title", "description"):
        full_schema.pop(attr)

    # Remove any definitions that aren't relevant to the CNA container (mainly cveMetadata*)
    for attr in ("cveMetadataRejected", "cveMetadataPublished", "dataType", "dataVersion"):
        full_schema["definitions"].pop(attr)

    # Remove global oneOf attribute that sets up the full record schema. The container-level
    # schema of a specific container is placed in the global context below.
    full_schema.pop("oneOf")

    container_to_filename = {
        "cnaRejectedContainer": "rejected_cna_container",
        "cnaPublishedContainer": "published_cna_container",
        "adpContainer": "adp_container",
    }
    for object_name, file_name in container_to_filename.items():
        # Save the objects from which we'll create the subschema
        container_object = full_schema["definitions"].pop(object_name)

        # Create a copy of the full schema
        object_schema = copy.deepcopy(full_schema)

        # Wipe out the other two objects (provide default of None for the object that we already
        # popped above).
        for attr in container_to_filename.keys():
            object_schema["definitions"].pop(attr, None)

        create_sub_schema(object_schema, container_object, f"{file_name}_{schema_version}.json")
