# Changelog

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

* Initial public release
