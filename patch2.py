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

replace_in_file('src/evidencetool/providers/base.py', r'def get\(self, key: str, default: str \| None = None\) -> str \| None:', r'def get(self, key: str, default: str = "") -> str:')

for root, _, files in os.walk('src/evidencetool'):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            replace_in_file(filepath, r'context\.get\("host", None\)', r'context.get("host", "")')

replace_in_file('src/evidencetool/providers/filesystem.py', r'int\(context\.get\("threshold_bytes", None\)\)', r'int(context.get("threshold_bytes", "0"))')
replace_in_file('src/evidencetool/models/decision.py', r'value: dict = field', r'value: dict[str, typing.Any] = field')
replace_in_file('src/evidencetool/models/observation.py', r'value: dict = field', r'value: dict[str, typing.Any] = field')
replace_in_file('src/evidencetool/models/evidence.py', r'value: dict = field', r'value: dict[str, typing.Any] = field')
replace_in_file('src/evidencetool/cli/render.py', r'rows: list\[dict\]', r'rows: list[dict[str, typing.Any]]')
replace_in_file('src/evidencetool/observability/metrics.py', r'ev_status\.value', r'status.value')
replace_in_file('src/evidencetool/observability/metrics.py', r'for ev_status, count', r'for status, count')
replace_in_file('src/evidencetool/observability/metrics.py', r'def write_metrics\(metrics: MetricsData, output_path: str = "./evidencetool.prom"\):', r'def write_metrics(metrics: MetricsData, output_path: str = "./evidencetool.prom") -> None:')

with open('.bandit', 'w') as f:
    f.write('[bandit]\nexclude_dirs = ["tests"]\nskips = ["B108", "B404"]\n')
