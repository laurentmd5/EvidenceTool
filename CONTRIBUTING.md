# Contributing to EvidenceTool

Welcome! Before contributing, please review the strict invariants of this project. EvidenceTool's value is derived from its constraints. Any PR violating these invariants will be rejected, regardless of its utility.

## Non-Negotiable Invariants

1. **No shell=True**: A provider must never build a shell command as a string. Always use lists `["command", "arg"]`. This prevents shell injection vulnerabilities.
2. **Provenance is Mandatory**: Every `Observation` must carry its provenance: who collected it, how, and from where (`collector`, `method`, `host`).
3. **Immutable Decisions**: A `Decision` must never be modified after it is made. It cannot be influenced by a `Recommendation`.
4. **Precedence Rule**: `BLOCK > HUMAN_REVIEW > ALLOW`. This is always true, without exception.
5. **Fail-Closed Ambiguity**: In `V2_SITUATIONAL`, if evidence is UNKNOWN for an evaluated hypothesis and no blocking situation matches, the situation is ambiguous and the engine must FAIL CLOSED (`BLOCK`).
6. **Local Uncertainty**: Uncertainty is local to the hypothesis it affects. An `UNKNOWN` evidence in an unrelated domain does not contaminate a clean, verified decision in the target domain.
7. **Transport Failure is Not Component Failure**: Network timeouts, connection resets, or HTTP 403 authorization failures on probe APIs (e.g. `kubectl`) degrade to `UNKNOWN` (`transport_status="failed"`), never to component defect (`FAIL`). Absence of evidence is not evidence of failure.
8. **Tests are Required**: Any new provider or situation MUST be accompanied by unit tests, schema validation, and where applicable, E2E tests.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

Please run `pytest tests/` and ensure the CI checks pass before submitting a PR.
