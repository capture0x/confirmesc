"""confirmesc - a Linux privilege-escalation enumerator that *confirms* findings.

Unlike LinEnum/linpeas, every finding here carries a Confidence level based on
facts actually observed on the running system (file permissions, capabilities,
exact version matches) rather than a raw dump of "things that might be
interesting". See README.md for design rationale.
"""

__version__ = "0.1.0"
