# Security policy

`verify.py` is meant to be run against evidence you didn't create,
including evidence you may not trust. That makes correctness here a
security property, not just a quality one: a verifier that can be
tricked into printing `VERIFIED` for a tampered packet is a bigger
problem than almost any other kind of bug in this project.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a
public issue -- in particular, anything in the following classes:

- a tampered packet (modified event, receipt, or document) that still
  produces `VERIFIED` / exit code 0;
- a valid packet that produces `VERIFICATION FAILED` (a false positive
  failure is a lesser but still real problem);
- any code path in `verify.py` that reaches the network, the filesystem
  outside the packet directory, or a dependency beyond the standard
  library and `cryptography`.

Email: chatftx@gmail.com with a description and, if possible, a minimal
packet reproducing the issue. We aim to acknowledge within 3 business
days.

## Scope

In scope: `verify.py`, `SPEC.md` (as the contract `verify.py` implements),
`generate_demo_packet.py` (only insofar as a bug there could produce a
misleadingly "valid" demo packet).

Out of scope: the private ActaSeal gateway/policy/ledger product that
produces real packets -- this repo does not contain it.
