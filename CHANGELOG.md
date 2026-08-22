# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-08-22
### Added
- V2 Situational Policy Engine: Evaluates operational states based on correlated evidence forming known situations.
- Detailed JSON schema for diagnosis results (`schemas/diagnosis-result.schema.json`).
- Dynamic provider registry to load custom providers automatically.
- Enhanced Nginx and TLS providers resilient to read-only execution constraints.

### Changed
- Refactored `engine.py` to evaluate explicit blocking situations before concluding ambiguous states.
- Reordered `nginx-v2.yaml` policy list to prioritize specific root causes (e.g. missing certificates) over generic errors.
- Unified decision precedence strictly to `BLOCK > HUMAN_REVIEW > ALLOW`.

## [0.2.0] - 2026-08-14
### Added
- Agentless remote execution over SSH (`--host` flag).
- `test_integrity.py` and structural invariant guarantees.

## [0.1.0] - Initial Release
### Added
- Core Evidence, Policy, and Decision models.
- V1 Legacy policy engine.
- Vertical slice for Nginx diagnostics (Scenarios A, B, C, D).
- CLI implementation.
