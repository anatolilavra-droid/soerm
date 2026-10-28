# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (current `main`) | yes |
| anything older | no |

Only the latest release line receives security fixes. SOERM has not published a release yet;
until it does, fixes land on `main`.

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability** (GitHub private vulnerability reporting). Do not open a
public issue, pull request or discussion for a suspected vulnerability.

Please include:

- the affected version or commit;
- the component (importer, redaction, storage, audit chain, approvals, reports, TUI, release
  tooling);
- steps to reproduce with **synthetic** data and the observed and expected behaviour;
- the impact you expect (for example a secret persisted unredacted, a path outside the
  workspace read or written, an audit chain change that `soerm audit verify` misses).

## Never publish real secrets

Do not put real secrets, credentials, tokens, private keys, customer data or real scan output
in issues, pull requests, discussions, commits or vulnerability reports. Describe the
**kind** of secret and its format instead, or replace it with a clearly fake value.

If a real secret was published by mistake, treat it as compromised: revoke or rotate it first,
then report it privately. A real secret is never added to the repository's allowlist of
test fixtures; it is removed from the repository and its history.

## Disclosure policy

SOERM follows coordinated disclosure:

1. The report is acknowledged within 7 days.
2. An initial assessment (accepted or declined, with severity) follows within 14 days.
3. Within 90 days of the report a fix is released or, if a fix is not ready, the status of
   the issue is published; actively exploited issues are handled faster. Fixes are prepared
   privately.
4. The fix is released together with a security advisory that describes the issue, the
   affected versions and the upgrade path. Reporters are credited unless they ask not to be.

Please do not disclose the issue publicly before the advisory is published or the 90 days
have passed, whichever comes first, unless agreed otherwise.

## Scope

SOERM is a local, offline tool. Its threat model and documented residual risks (pattern-based
redaction, command-line arguments in shell history, advisory file locking, an audit chain
without an external anchor) are described in `README.md`. Reports about these documented
limitations are welcome when they show a concrete bypass or a gap in the documentation.
