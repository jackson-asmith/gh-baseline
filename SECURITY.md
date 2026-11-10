# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**[Report a vulnerability](https://github.com/jackson-asmith/gh-baseline/security/advisories/new)**
(the repository's **Security** tab → **Report a vulnerability**).

Please don't open a public issue for a security problem.

Useful details: the gh-baseline version (`gh extension list`), the command
you ran, and what happened compared with what you expected.

## Supported versions

Fixes go into the latest release. Upgrade with `gh extension upgrade baseline`.

## What counts

gh-baseline is read-only and runs with your GitHub token, so the most
important reports are about:

- **Token handling:** the token being sent anywhere other than the GitHub API
  host, logged, or written to a snapshot.
- **Secrets:** anything beyond secret *names* being read or stored. The tool
  never reads secret values.
- **Wrong passes:** a check reporting `pass` when the repository doesn't meet
  it. A security tool that misses a problem is a vulnerability.
- **Release integrity:** published binaries that don't match the source.

Bugs that make a check fail when it should pass are welcome as regular
issues.
