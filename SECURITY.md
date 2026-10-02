# Security Policy

confirmesc is a tool for authorized security testing. This policy is about
vulnerabilities in confirmesc itself, not about the escalation techniques it
reports on a target.

## Reporting a vulnerability

Please report responsibly:

- Open a private security advisory from the repository's **Security** tab, or
- Open an issue that describes the class of problem without a working exploit.

Please do not publish a working exploit before a fix is available.

## Scope

In scope: bugs in confirmesc that could harm the operator's own system, produce
a false `CONFIRMED` finding, or run a command the operator did not intend.

Out of scope: the privilege-escalation techniques confirmesc reports on a
target. Surfacing those is the purpose of the tool, and they are only for
systems you are authorized to test.
