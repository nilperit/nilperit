# Security policy

NilPerit is pre-alpha software. Do not use it for real data yet.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub: go to the **Security** tab of this repository and choose **"Report a vulnerability"**. Only the maintainers can see the report.

Please include:

- a description of the problem and its impact;
- the affected component (for example the vault format, cryptography, a connector, the node, or the UI);
- steps to reproduce, or a proof of concept, if you have one.

We will acknowledge your report as soon as we can, keep you informed, and credit you when the fix is published, unless you prefer to stay anonymous.

## Scope

Of particular interest:

- weaknesses in the vault format or the key hierarchy (see [`docs/FORMAT.md`](docs/FORMAT.md));
- ways for a node to read stored content without the read key;
- ways for one damaged or malicious file to corrupt or hide unrelated data;
- leaks of keys, plaintext or metadata through logs, errors or the API.

## Supported versions

There are no releases yet. Security fixes go to the `main` branch.
