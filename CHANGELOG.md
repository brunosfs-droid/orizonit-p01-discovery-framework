# Changelog

All notable changes to the P01 Discovery Framework are documented here.

The project follows [Semantic Versioning](https://semver.org/) where practical.

## [Unreleased]

### Planned
- Linux collector validation
- Shared discovery schema validation
- Central orchestrator
- Automated test matrix
- Analyzer and reporting pipeline

## [0.2.1] - 2026-09-29

### Fixed
- Windows PowerShell 5.1 compatibility for Generic List conversion
- Explicit conversion of collector errors, limitations and warnings with `.ToArray()`
- Network IP configuration list conversion
- Metadata counters now use the converted arrays

## [0.2.0] - 2026-09-29

### Added
- Explicit errors, limitations and warnings collections
- Expanded runtime and privilege metadata
- Improved network discovery structure
- AD/GPO optional collection behavior

## [0.1.0] - 2026-09-28

### Added
- Initial Windows/AD discovery collector
- JSON output
- SHA-256 integrity file
- Initial laboratory validation
