Security policy

If you discover a security vulnerability in this project, please do not open a public issue. Instead, contact the project owner directly and provide a minimal repro and suggested mitigations.

Suggested contact process
- Send an email to the project owner or GitHub account with subject `Security report: thingdb`.
- Include steps to reproduce, affected versions, and any proof-of-concept code.
- If you need to share sensitive information, request a secure channel.

Disclosure timeline
- The project maintainer will acknowledge receipt within 72 hours and work with the reporter to triage and remediate.

Security best practices for contributors
- Do not commit private keys, tokens, or credentials. Use the provided `.gitignore`.
- Store CI secrets in GitHub Actions Secrets; never hardcode credentials.
