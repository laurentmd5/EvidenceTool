import os
import re


def replace_in_file(filepath, pattern, replacement):
    with open(filepath, 'r') as f:
        content = f.read()
    new_content = re.sub(pattern, replacement, content)
    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f'Updated {filepath}')

for root, _, files in os.walk('src/evidencetool'):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            # Fix value: dict = field -> value: dict[str, typing.Any] = field
            replace_in_file(filepath, r'value: dict = field', r'value: dict[str, typing.Any] = field')
            # Fix def _now(): -> def _now() -> datetime:
            replace_in_file(filepath, r'def _now\(\):', r'def _now() -> datetime:')

            # fix missing return None on __init__
            replace_in_file(filepath, r'def __init__\(self\):', r'def __init__(self) -> None:')

# decision.py, observation.py, evidence.py need typing.Any
for file in ['decision.py', 'observation.py', 'evidence.py']:
    replace_in_file(f'src/evidencetool/models/{file}', r'from dataclasses import', r'import typing\nfrom dataclasses import')

replace_in_file('src/evidencetool/cli/render.py', r'def _print_table\(title: str, rows: list\[dict\], color: str = "white"\):', r'def _print_table(title: str, rows: list[dict[str, typing.Any]], color: str = "white") -> None:')
replace_in_file('src/evidencetool/cli/render.py', r'import click', r'import click\nimport typing')
replace_in_file('src/evidencetool/cli/main.py', r'def init_cmd\(\):', r'def init_cmd() -> None:')

replace_in_file('src/evidencetool/observability/metrics.py', r'def write_metrics\(metrics: MetricsData, output_path: str = "\./evidencetool\.prom"\):', r'def write_metrics(metrics: MetricsData, output_path: str = "./evidencetool.prom") -> None:')
replace_in_file('src/evidencetool/observability/metrics.py', r'for status, count in metrics\.evidence_status_counts\.items\(\):', r'for ev_status, count in metrics.evidence_status_counts.items():')
replace_in_file('src/evidencetool/observability/metrics.py', r'status\.value', r'ev_status.value')

replace_in_file('src/evidencetool/models/evidence.py', r'PASS = "PASS"', r'PASS = "PASS"  # nosec B105')
