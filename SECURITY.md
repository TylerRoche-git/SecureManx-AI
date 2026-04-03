# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecureManx AI, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@securemanx.dev**

Or use [GitHub's private vulnerability reporting](https://github.com/TylerRoche-git/SecureManx-AI/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: as soon as reasonably possible, coordinated with you

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Considerations

SecureManx AI is itself a security-critical component. Its control plane has privileged access to enforcement infrastructure and is a high-value attack target. The architecture addresses this with:

1. **Sentinel** &mdash; internal self-attestation (binary and policy hash verification)
2. **Watchdog** &mdash; external monitor that kills the control plane if tampered
3. **Deterministic policy gate** &mdash; AI reasoning cannot directly trigger enforcement
4. **Append-only audit trail** &mdash; all decisions and actions are immutably logged
5. **Minimal adapter surface** &mdash; adapters communicate only via NATS, not direct API calls

### Deployment hardening

- Run the control plane in a dedicated namespace with strict RBAC
- Use signed container images and admission controllers
- Restrict network access to the control plane API
- Enable TLS for NATS and PostgreSQL connections in production
- Set `WEBHOOK_SECRET` for CI adapter webhook verification
- Run the watchdog binary on a separate node or host from the control plane
