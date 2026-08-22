# Contributing to EvidenceTool

Welcome! Before contributing, please review the strict invariants of this project. EvidenceTool's value is derived from its constraints. Any PR violating these invariants will be rejected, regardless of its utility.

## Non-Negotiable Invariants

1. **No shell=True**: A provider must never build a shell command as a string. Always use lists `["command", "arg"]`. This prevents shell injection vulnerabilities.
2. **Provenance is Mandatory**: Every `Observation` must carry its provenance: who collected it, how, and from where (`collector`, `method`, `host`).
3. **Immutable Decisions**: A `Decision` must never be modified after it is made. It cannot be influenced by a `Recommendation`.
4. **Precedence Rule**: `BLOCK > HUMAN_REVIEW > ALLOW`. This is always true, without exception.
5. **Fail-Closed Ambiguity**: In `V2_SITUATIONAL`, if evidence is UNKNOWN and no blocking situation matches, the state is ambiguous and the engine must FAIL CLOSED (`BLOCK`).
6. **Tests are Required**: Any new provider or situation MUST be accompanied by unit tests and, where applicable, E2E tests.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

Please run `pytest tests/` and ensure the CI checks pass before submitting a PR.
