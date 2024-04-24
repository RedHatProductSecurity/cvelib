# CVE v5 JSON Record Examples

The example CVE records in this directory are copied from: https://github.com/CVEProject/cve-schema

They should be kept up to date with the schema versions in `cvelib/schemas/`.

The `container-*` files are standalone CNA or ADP (the two differ only in the set of required attributes) containers
that were extracted from their respective full CVE record files:

```shell
jq .containers.cna CVEv5_advanced-example.json > container-advanced-example.json
jq .containers.cna CVEv5_basic-example.json > container-basic-example.json
```
