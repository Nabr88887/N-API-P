# Security Policy

## Supported Versions

N-API-P is currently alpha software. Security fixes target the latest commit on
`main` and the newest tagged release, when available.

## Do Not Open a Public Issue for a Vulnerability

Do not include credentials, tokens, real prompts or responses, database
contents, internal hostnames, or deployment secrets in a public issue.

Use GitHub's private vulnerability reporting or Security Advisory feature for
this repository. If private reporting is unavailable, contact the maintainer
through the GitHub profile without sending sensitive details in the first
message.

## Include in a Private Report

- Affected version or commit
- A minimal, synthetic reproduction
- Expected and observed behavior
- Security impact and required preconditions
- Whether any real credential or production data was exposed

## Never Include

- Live API keys or passwords
- Raw production request or response content
- Database dumps
- Audit encryption material
- Personally identifying employee data

## Deployment Boundary

The repository examples are templates. Operators are responsible for TLS,
host access control, database protection, secret-file permissions, backup
policy, monitoring, upgrades, and provider terms.
