# Security policy

`agent-trust` is an **experimental research laboratory**. It is not a
production authorization, identity, or messaging product. Do not deploy it as
a network service, expose the authority CLI, or treat passing tests as a
cryptographic proof.

## Supported versions

Only the default branch (`main`) is reviewed. There are no stable releases and
no security-support window.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.

1. Use GitHub's private vulnerability reporting on
   [dasobral/agent-trust](https://github.com/dasobral/agent-trust/security/advisories/new)
   if it is available; or
2. Email the maintainer listed in [`MAINTAINERS`](MAINTAINERS).

Include enough detail to reproduce the issue, expected versus observed
behavior, and whether the finding affects the durable authority kernel, the
OpenMLS laboratory, the independent Python oracle, or documentation claims.

Do not attach private keys, live credentials, or real endpoint configuration.

## Claim boundary

A green test run shows that the executed gates passed. It does not establish
`full_lap_mls`, retained-key exclusion for untested schedules, or production
MLS authorization-domain coupling. See the README claim-boundary section and
[`docs/specification.md`](docs/specification.md).
