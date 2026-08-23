# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-08-23
### Added
- **Network Provider (`network`)**: Added connection checks for `network.port_reachable`, `network.host_reachable`, and `network.dns_resolvable` (supporting local sockets and agentless remote execution).
- **Process Provider (`process`)**: Added process checks for `process.running` (with PID tracking) and `process.zombie` (zombie state detection).
- **Filesystem Provider Enhancement**: Added `filesystem.disk_pressure` for early disk saturation detection.
- **New Situations**: Defined `DISK_PRESSURE`, `NETWORK_UNREACHABLE`, `PROCESS_CRASHED`, and `PROCESS_HEALTHY` signatures in `catalogs/system.yaml` and `catalogs/nginx.yaml`.
- **System Catalog**: Added generic system-level catalog (`catalogs/system.yaml`).

## [0.4.0] - 2026-08-22
### Added
- **Docker Multi-environment Provider (`docker` / `container`)**: Strict read-only container inspection supporting `container.exists`, `container.running`, `container.restarting`, `container.health`, `container.exit_code`, and `container.logs`.
- **Docker Situation Catalog (`catalogs/docker.yaml`)**: Defined signatures for `CONTAINER_HEALTHY`, `CONTAINER_STOPPED`, `CONTAINER_CRASH_LOOP`, `CONTAINER_UNHEALTHY`, and `CONTAINER_NOT_FOUND`.
- **Docker Policy (`policies/docker.yaml`)**: Added default policy for container restart actions.
- **Docker E2E Test Suite (`tests/e2e/run_docker_e2e.sh`)**: Real container testing with crash loop, unhealthy healthcheck, and stopped container scenarios.
- **Contract Formalization**: Documented Docker socket privilege trade-off and read-only guardrails in Section 15 of `PRODUCT_CONTRACT.md`.

## [0.3.0] - 2026-08-22
### Added
- V2 Situational Policy Engine: Evaluates operational states based on correlated evidence forming known situations.
- Detailed JSON schema for diagnosis results (`schemas/diagnosis-result.schema.json`).
- Dynamic provider registry to load custom providers automatically.
- Enhanced Nginx and TLS providers resilient to read-only execution constraints.
- Multi-distribution CI support (Ubuntu 22.04 LTS + Debian 12).
- Agent Harness Integration Guide (`docs/integrations/agent-harness.md`).

### Changed
- Refactored `engine.py` to evaluate explicit blocking situations before concluding ambiguous states.
- Reordered `nginx.yaml` policy list to prioritize specific root causes (e.g. missing certificates) over generic errors.
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
