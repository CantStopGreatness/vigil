# Security policy

Vigil is a security tool, so vulnerabilities in it matter, especially anything that lets the
public web dashboard reach internal networks (SSRF), leak other users' reports, or run script
in a viewer's browser.

## Reporting a vulnerability

Please report privately through GitHub's **Security → Report a vulnerability** on this
repository rather than opening a public issue. Include steps to reproduce and the version or
commit you tested. You should get a response within a few days.

## Scope

In scope: the `vigil` package, the web dashboard and API, and the Docker image.
Out of scope: findings Vigil reports about *other* websites, and deployments running with
`VIGIL_ALLOW_PRIVATE=1` (that setting deliberately disables SSRF protection for local use).
