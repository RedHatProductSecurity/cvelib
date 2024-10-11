# Changelog

## [1.6.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.5.0...1.6.0) (Oct 11, 2024)

* Subcommands that not require authentication credentials no longer require `-u/-o/-a` options to be set (#93).

## [1.5.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.4.0...1.5.0) (Jul 18, 2024)

* The `-u/--username` option is now required when updating a user or resetting the token of a user (#86).
* Updated CVE record schemas to final 5.1.0 version; the previous 5.1.0 were still RC versions that later changed (#87).
* The called command is shown in an error message that refers users to read help text (#84).

## [1.4.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.3.0...1.4.0) (May 15, 2024)

* Updated CVE JSON schema to version 5.1.0, which makes it compatible with CVE Services 2.3.x (#79).

## [1.3.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.2.1...1.3.0) (Jan 26, 2024)

* Fixed displaying timestamps for older records (#66).
* Added auto-completion of sub-commands (#73).
* Added support for ADP containers (#70):
  * A new `publish-adp` command is added that allows publishing of ADP containers into an existing CVE record (this is
    only possible if a CVE is in the published state).
  * The `show` subcommand now allows displaying a CNA container or all/subset of existing ADP containers (identified by
    the org's name that created it).
  * ADP containers can only be published and updated, so there is no functionality to remove them.
* CVE state constants were updated to match the case used by CVE Services, e.g. `rejected` -> `REJECTED` (#75).
* Fixed displaying CVE ID reservations for records that are missing the `user` attribute (#76).

## [1.2.1](https://github.com/RedHatProductSecurity/cvelib/compare/1.2.0...1.2.1) (Feb 16, 2023)

* Improved `CveRecordValidationError` exception error message.

## [1.2.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.1.0...1.2.0) (Dec 2, 2022)

* The `list` and `users` commands have a new `-N/--no-header` option that skips printing a header in the table
  output. (#55).
* The bundled CNA Published JSON schema is used by default when calling `CveRecord.validate()` (#57).
* The `jsonschema` required dependency was relaxed to an older version (#54).

## [1.1.0](https://github.com/RedHatProductSecurity/cvelib/compare/1.0.0...1.1.0) (Nov 11, 2022)

* The `publish` and `reject` subcommands have a new `-f/--cve-json-file` option that allows submitting CVE records from
  a file (#18).
* Added CVE v5 JSON schema (5.0.0) validation when publishing a CVE record (#39).
* Full CVE v5 records can now be used when publishing a CVE; the CNA container is parsed from the CVE record
  automatically (#42).
* Automatically add `providerMetadata` from the org used when authenticating against CVE Services if it is missing in
  the supplied CVE record (#19).
* Added CVE v5 JSON 5.0.0 schemas under `cvelib/schemas` along with a script that extracts container-level sub-schemas.
* `cve show --show-record --raw` now outputs a valid CVE record only (#44).
* Dropped support for Python 3.6.

## [1.0.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.7.0...1.0.0) (Oct 3, 2022)

* Added support for CVE Services 2.1:
  * New subcommands: `publish`, `reject`, `undo-reject`.
  * The `show` subcommand now includes a `--show-record` option to view a CVE's record.
  * Added several new methods in the `CveApi` interface to reflect new CVE Services API endpoints.
* Fixed sorting by the reserved timestamp when using the `list` subcommand.

## [0.7.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.6.0...0.7.0) (Feb 6, 2022)

* Reverted commit c1f5edeb2cb1a39dfbab1813a3bc68ae4c04661d, which is (for
  now) incompatible with the currently available version of CVE Services.

## [0.6.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.5.0...0.6.0) (Dec 17, 2021)

* Added prompt for API key if not specified via env var or option (#13).
* Updated list of environments to include "test".
* Renamed `reset_token` subcommand to `reset_key`.

## [0.5.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.4.0...0.5.0) (Oct 25, 2021)

* Fixed API key not being returned when creating a new user (#8).

## [0.4.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.3.0...0.4.0) (Jun 15, 2021)

* Added `cve org` command.
* Added `cve user` command.
* Refactored `Idr` interface into a general `CveApi` interface.
* Fixed error when showing a CVE that is owned by a different CNA.

## [0.3.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.2.0...0.3.0) (Jan 18, 2021)

* Fixed incorrect parsing of timestamps when using Python 3.6 (#1).

## [0.2.0](https://github.com/RedHatProductSecurity/cvelib/compare/0.1.0...0.2.0) (Jan 14, 2021)

* Fixed missing org query parameter when reserving a CVE ID.
* Improved printing of reserved CVE IDs after they are reserved.
* Improved `quota` subcommand documentation and output.

## [0.1.0](https://github.com/RedHatProductSecurity/cvelib/tree/0.1.0) (Dec 23, 2020)

* Initial public release.
