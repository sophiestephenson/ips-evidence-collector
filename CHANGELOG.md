# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Structure:
Added for new features.
Changed for changes in existing functionality.
Deprecated for soon-to-be removed features.
Removed for now removed features.
Fixed for any bug fixes.
Security in case of vulnerabilities.

## [v1.1.0] - August 5, 2025

### Added     

### Changed
- Major restructuring: Moved all Sherloc code into the `sherloc` folder.
- `isdi` file now renamed `main.py`.
- Created `./sherloc.sh` run script, which creates and activates a virtual environment, installs requirements if needed, and runs Sherloc in sudo (via `main.py`).
- Updated `README`.
- Resumed using this changelog.

### Deprecated
### Removed
- Unused files and folders, mostly .pngs in `webstatic/images`.
- Removed `libimobiledevice` from `Brewfile`. 

### Fixed
### Security
