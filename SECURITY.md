# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Yes |
| 0.0.x | ❌ No  |

## Reporting a Vulnerability

If you discover a security vulnerability in BaseSec itself (not just a rule detecting vulnerabilities in code):

1. **Do not open a public issue.**
2. Email the maintainer directly at [tavotsudev@gmail.com] with:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

You will receive a response within 48 hours acknowledging receipt.

## Security Measures

- BaseSec is a **read-only** tool. It never writes to, modifies, or executes your source code.
- All AST analysis happens in-memory. No source code leaves your machine.
- Worker threads run in isolated V8 contexts without access to the main thread's memory.
- Cache files are stored locally in `os.tmpdir()` with hashed filenames.

## False Positives and Negatives

BaseSec uses static analysis, which has inherent limitations:

- **False positives** — Safe code may be flagged due to conservative pattern matching
- **False negatives** — Runtime-dependent vulnerabilities may not be detected
- **Taint analysis limitations** — Complex control flow, dynamic imports, and reflective code may bypass detection

BaseSec is a defense-in-depth tool, not a replacement for code review, penetration testing, or runtime protection.

## Rule Severity

Rules are classified by severity:

- **Critical** — Immediate action required. High likelihood of exploitation.
- **High** — Serious vulnerability. Should be fixed before release.
- **Medium** — Moderate risk. Fix in next maintenance cycle.
- **Low** — Minor issue. Address when convenient.
- **Info** — Informational. No action required.

## Disclosure Policy

- Vulnerabilities will be patched as quickly as possible
- A security advisory will be published for critical and high severity issues
- Credit will be given to reporters who wish to be acknowledged

## Acknowledgments

Security audit and bug fixes for v0.1.0 were conducted as part of the initial release process.