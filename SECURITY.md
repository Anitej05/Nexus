# Security policy

## Supported status

NEXUS `0.x` is a local-development prototype. No version is currently supported for production
deployment, internet exposure, regulated workloads, or storage of real customer data.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting or private security-advisory flow for this
repository. Do not open a public issue containing exploit instructions, credentials, access
tokens, personal data, or other sensitive evidence.

If private vulnerability reporting is unavailable, contact the repository owner through the
[Anitej05 GitHub profile](https://github.com/Anitej05) and request a private reporting channel.
Do not include vulnerability details, proof-of-concept material, or sensitive evidence in that
public request. Private vulnerability reporting remains the preferred route.

Include the affected commit, component, impact, reproduction prerequisites, and the smallest safe
proof of concept. You should receive an acknowledgement within five business days. Please allow a
reasonable remediation and disclosure-coordination period before publishing details.

Ordinary bugs without security impact may be reported through GitHub Issues.

## Local-development boundaries

- Compose services are intended only for loopback access and bind published ports to `127.0.0.1`.
- `.env.example` contains recognizable development placeholders, not production secrets. Copy it
  to ignored `.env`, replace every placeholder, and never commit the result.
- Keycloak runs in development mode and the broader stack includes development-only service modes.
- The LLM is advisory and receives bounded cited facts, but operators remain responsible for the
  confidentiality and terms of any configured provider.
- Prototype actions are simulated. Connecting real actuators or external systems is outside the
  supported threat model.

If a credential is accidentally committed, revoke or rotate it first; deleting the current file
does not remove it from Git history.
