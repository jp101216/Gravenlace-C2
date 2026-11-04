# Security reporting

The management service is experimental and has no verified production release. Its intended access boundary is host loopback. It does not provide TLS or remote team access.

The recovered research source is excluded from that service's build and has the open findings recorded in [research/REVIEW_NOTES.md](research/REVIEW_NOTES.md). Management CI is not a security audit of those files.

When published, use GitHub's private vulnerability-reporting option if the repository enables it. Otherwise request a private contact method in a public issue without including sensitive details. No reporting email or response deadline is established here.

Do not post bearer tokens, secret files, environment data, or private system details. A report should identify the affected revision, impact, and a minimal non-sensitive reproduction.
