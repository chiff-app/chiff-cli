# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2024-09-07

### Fixed

- Fixed a bug where a request id could not be generated on python 3.12.

## [0.3.0] - 2024-06-16

### Changed

- Updated the help text for generating SSH keys to make it more compatible with Android.
- Updated dependencies.

## [0.2.2] - 2022-11-25

### Fixed

- Fixed a bug where request sent to the wrong endpoint for the staging version of the app.

## [0.2.1] - 2022-10-26

### Fixed

- Fixed #6, where the SSH socket broke for OpenSSH >= 8.9 in case `SSH_AUTH_SOCK` was set.

## [0.2.0] - 2022-09-7

### Added

- Version flag (chiff --version)
- Added a command to get all accounts in a format that [Alfred](https://www.alfredapp.com) understands, so you can use it in a workflow.

### Fixed

- Fixed #6, where the SSH socket broke for OpenSSH >= 8.9.

## [0.1.0] - 2021-08-11

### Added

- Initial version
