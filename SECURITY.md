# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MedEvac, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Contact

Email: [b.alhaddad13@gmail.com](mailto:b.alhaddad13@gmail.com)

Subject line: `[SECURITY] MedEvac - Brief description`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 7 days
- **Fix:** Critical issues within 14 days, others within 30 days

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Security Measures

MedEvac implements the following security controls:

- **Authentication:** Firebase Anonymous Auth + server-side PIN verification (PBKDF2, 100K iterations)
- **Rate limiting:** Progressive lockout after failed PIN attempts (client + server)
- **Encryption at rest:** AES-GCM 256-bit for local cached data
- **Encryption in transit:** HTTPS-only with TLS 1.2 minimum
- **Content Security Policy:** Restrictive CSP with allowlisted domains
- **Input validation:** Client-side + Firebase database security rules
- **Privacy:** Civil ID masking, auto-lock timeout, privacy blur on background
- **Audit trail:** All security-relevant actions logged
- **iOS ATS:** No arbitrary loads, forward secrecy required
- **Android:** Cleartext traffic disabled
