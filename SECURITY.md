# Security policy

## Reporting a flaw in this project

Use the repository's **Security → Report a vulnerability** option when available
for issues needing private disclosure. Otherwise contact CompleteTech LLC
through [complete.tech](https://complete.tech) to arrange private reporting.
Include the affected commit, a minimal local reproduction, expected and actual
behavior, and impact. Omit credentials, real target lists, and third-party data.
Do not publish sensitive details in a public issue while private review is underway.

Only the current default branch is maintained. Reproduce against its latest
revision when possible. No response-time guarantee is made.

## Advisory scope and implementation status

This project is dedicated to **CVE-2026-96889**. Its offline checker assesses
explicit operator-provided evidence. It does not execute applications, decode
images, make network requests, test exploitability or detect prior compromise.

Output distinguishes reported versions and configuration observations from
confirmed exposure. Exploitability remains `not_tested`. Use assessment
features only for authorized assets; project development alone authorizes no
network scanning. Keep real inventories and assessment results outside the repo.

A Sharp package number cannot attest a global librsvg, a vendor backport or a
custom build. Work from a stable evidence copy; bounded regular-file checks do
not provide an operating-system sandbox against concurrent filesystem changes.

For a vulnerability in the affected upstream product or a service you assess,
follow that vendor's or service owner's published security-reporting process.
