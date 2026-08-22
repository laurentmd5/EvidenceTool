# Security Policy

## Supported Versions

Currently, EvidenceTool is in pre-release (`0.3.0`). Security updates will be applied to the main branch. Once a stable release is cut (e.g. `1.0`), this table will reflect supported maintenance branches.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

**DO NOT** create a public GitHub issue for security vulnerabilities.
This tool accesses sensitive infrastructure, including private keys and production servers via SSH. We take security extremely seriously.

Please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/laurentmd5/EvidenceTool/security/advisories) or by contacting the maintainer directly at `laurent@mavoungou.net`.

We will acknowledge your report within 48 hours and provide a coordinated disclosure timeline.

## Scope
Vulnerabilities of high interest include:
- Shell injection in providers (building commands as strings instead of lists).
- Arbitrary file read/write or privilege escalation.
- Circumvention of `Decision` integrity (forcing an `ALLOW` on invalid or ambiguous states).
- Any leakage of private keys or sensitive credentials inspected during diagnosis.
