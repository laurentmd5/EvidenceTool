# Security Policy

## Supported Versions

Currently, EvidenceTool is in release (`1.0.2`). Security updates are applied to the development and main branches.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

## Reporting a Vulnerability

**DO NOT** create a public GitHub issue for security vulnerabilities.
This tool accesses sensitive infrastructure, including private keys and production servers via SSH. We take security extremely seriously.

Please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/laurentmd5/EvidenceTool/security/advisories) or by contacting the maintainer directly at `mercilaurentmavoungou@gmail.com`.

We will acknowledge your report within 48 hours and provide a coordinated disclosure timeline.

## Scope
Vulnerabilities of high interest include:
- Shell injection in providers (building commands as strings instead of lists).
- Arbitrary file read/write or privilege escalation.
- Circumvention of `Decision` integrity (forcing an `ALLOW` on invalid or ambiguous states).
- Any leakage of private keys or sensitive credentials inspected during diagnosis.
