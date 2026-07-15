# The Offline-Verifiable Dispute Packet

### A technical note on evidence for agent-initiated payments

*actaseal-verify project — see the repository root for the verifier, spec, and demo packets referenced throughout.*

---

## 1. Summary

AI agents are being given standing authority to initiate payments, and
the card networks are simultaneously tightening how they measure and
penalize disputes. The infrastructure to *resolve* a dispute over an
agent-initiated transaction — to say with evidence what the agent was
authorized to do, what it actually did, and whether those match — is not
something any dispute-management vendor currently ships as a public,
independently verifiable artifact.

This document describes one candidate for that artifact: a **dispute
packet** — a small, self-contained file bundle that a payment gateway
produces at the moment it makes a policy decision about an agent action,
and that any counterparty can verify offline, without installing vendor
software or trusting a vendor's server, months or years later.

Every technical claim below is demonstrable today against the public
`actaseal-verify` repository — the verifier, the packet format, and two
working demo packets (one with a payment-rail settlement anchor, one
without) are all in that repo. Where a claim describes something not yet
built, it is marked **(roadmap)**.

## 2. The problem: dispute infrastructure hasn't caught up to agent payments

### 2.1 The industry's own assessment

Chargebacks911 — a dispute-management vendor, cited here for its public
industry position, not as an independent authority — has publicly warned
that payment networks are activating AI-agent payment programs faster
than the infrastructure to manage disputes over agent-initiated
transactions is being built. Its stated argument: traditional dispute
resolution assumes a human made the purchase decision, with intent and
authorization determined by reference to what a cardholder chose to do
at the moment of transaction. When an agent acts autonomously on
delegated authority set at a prior point in time, without confirmation
at the moment of the transaction itself, that assumption doesn't hold.
Chargebacks911's own recommendation is telling: document authorization
*at the point of delegation*, not reconstruct it after a dispute is
filed — which is the same design principle this artifact is built
around. (Vendor-claimed; Chargebacks911 public statement, reported by
The Paypers and Finopotamus, 2026.)

### 2.2 The networks are raising the cost of getting this wrong

Independent of agent payments specifically, both major card networks
have materially tightened dispute-rate enforcement in 2026:

- **Mastercard's Scam Merchant Monitoring Program (SMMP)** reaches full
  effect on **24 July 2026**. Unlike ratio-based programs that give
  merchants time to remediate, SMMP is investigation-triggered: a
  combined refund-plus-chargeback rate above 5% (for newer merchants) or
  a fraud/scam signal can trigger a 72-hour acquirer investigation, and
  a confirmed finding terminates the merchant's Mastercard processing
  immediately rather than levying a fine. (Vendor/industry-reported; see
  Chargeback Gurus, Justt, and Equifax coverage of the program, 2026.)
- **Visa's Acquirer Monitoring Program (VAMP)** lowered its merchant
  threshold to a **1.5% VAMP ratio** (from 2.2%) effective April 2026,
  with acquirers facing a 0.7% threshold, and fines of roughly **$8 per
  disputed or fraudulent transaction** for merchants and acquirers over
  threshold. (Vendor/industry-reported; see Chargeflow and NMI coverage
  of VAMP, 2026.)
- **Global chargeback volume** is projected to grow from an estimated
  **261 million in 2025 to 324 million by 2028** — a roughly 24% increase
  in three years — per Mastercard and Datos Insights figures reported by
  Tearsheet. (Vendor/analyst-sourced.)

None of these programs distinguish between a human-initiated and an
agent-initiated transaction when counting toward the ratio. A merchant
or PSP that cannot quickly produce clean evidence for an agent-initiated
dispute pays the same penalty as one that cannot for a human-initiated
one — but has strictly less tooling built for the agent case today.

### 2.3 Why "reconstruct it later" doesn't work

The default state of most agentic-commerce integrations today is: an
agent framework logs its own reasoning trace somewhere, a payment
processor logs the transaction, and if a dispute arrives weeks later,
someone manually stitches these together from two systems that were
never designed to agree on a shared identifier, a shared timestamp
basis, or a shared notion of what "the agent was allowed to do" meant at
the moment it acted. Evidence assembled this way is neither tamper-
evident nor independently checkable — a counterparty has no way to
confirm the reconstruction wasn't shaped by the party being disputed
against.

## 3. The artifact: a durable, portable, offline-verifiable packet

The alternative this project implements: bind the evidence *at the point
of delegation and decision*, not after the fact. When a gateway makes a
policy decision about an agent's payment action — allow, block, require
approval — it can, at that moment, produce a **dispute packet**: a small
zip containing

- a hash-chained slice of the decision ledger covering the action,
- the signed receipt for the decision,
- an acquisition report and chain-of-custody document (who exported it,
  when, with what tool, from what source),
- an authentication statement binding the above together, and
- the verifier itself.

The packet is designed to be handed to a counterparty — an issuer, a
card network, a claims analyst, opposing counsel — at any point after
the fact, and checked without needing anything from the gateway operator
except the packet itself and, out of band, the operator's published
public key.

## 4. Three properties, in combination

Individually, offline verification, payment-anchor binding, and
evidence-rule-aware documentation each exist elsewhere in some form. The
claim here is about the combination, and about how each is implemented.

### 4.1 True zero-import verification

`verify.py`, the file that ships inside every packet, has no dependency
on this project's own product code, no dependency on a database, and no
network call anywhere in it — it reads only the files inside the packet
directory, plus the Python standard library and the third-party
`cryptography` package for signature checks. This isn't a claim you have
to take on faith: the file is roughly 360 lines, readable in one
sitting, and the public repo's test suite includes a static assertion
that it never imports anything beyond that. A counterparty who doesn't
trust the vendor doesn't have to trust the vendor's server, either —
they run the check themselves, on their own machine, against a copy of
the exact file that produced the `VERIFIED` result, because every packet
embeds that file's literal bytes, hash-pinned against the published copy
in this repository so the two cannot silently drift apart.

### 4.2 Payment-anchor binding

Where a settlement occurred, the packet can carry a settlement anchor —
a record of the payment rail, an anchor identifier, and a settlement
timestamp — bound to the same delegation mandate the policy decision was
made under via a shared `mandate_hash`. The demo packet
`demo-packet-anchored` in this repo shows the concrete shape of this: an
AP2-style mandate hash appearing identically in both the receipt and the
settlement anchor block, letting a verifier confirm the decision and the
settlement refer to the same authorization rather than merely asserting
that they do. `demo-packet-unanchored` shows the other honest state: no
settlement occurred, and the packet says so explicitly
(`SETTLEMENT_UNANCHORED`) rather than leaving the field blank or absent.

Live settlement on a production payment rail, beyond the demo construction
in this repo, is **(roadmap)**.

### 4.3 Evidence-rule mapping — carefully worded

The acquisition report, chain-of-custody document, and authentication
statement inside each packet are structured around the categories that
U.S. Federal Rules of Evidence 901(b)(9) and 902(13)–(14) address for
authenticating output from an electronic process or system and
self-authenticating certified records generated by such a process. The
packet is **designed to support self-authentication under FRE
902(13)/(14)** — it documents the acquisition tool, method, clock
source, and an unbroken custody chain, and it is structured so those
documents can back a certification consistent with those rules.

This is a design claim, not a legal one, and not a guarantee: **no
representation is made that any specific packet is court-admissible**,
and admissibility is decided by a court applying the relevant rules to
the specific facts of a specific case, not by this document or this
software. What is demonstrable today is the structure: the fields these
rules care about (tool, method, clock source, custodian, unbroken
chain) are present and checked by the verifier; the legal outcome is not
something software can certify on its own behalf.

## 5. The primitive: deterministic scope conformance, not post-hoc reconstruction

At the center of the decision-evidence pipeline is a specific, narrow
computation: given the scope of authority an agent was granted (an
*intent scope* — what kinds of actions, up to what amounts, for what
tenant) and the action the agent actually attempted to execute, compute
a deterministic verdict: `IN_SCOPE`, or a `BREACH` naming the specific
dimension exceeded (amount, action type, tenant boundary, etc.). Both
inputs are hashed independently and recorded; the verdict recomputes
from those recorded inputs, and the verifier checks that recomputation
rather than trusting a stored label.

This is a deliberately different approach from post-hoc reconstruction
via a model that reviews transcripts or logs after a dispute is filed
and estimates what likely happened. A model-based reconstruction can be
useful — it can surface things a rigid scope diff can't, like unusual
behavioral patterns — but its output is a probabilistic judgment made
after the fact, generally not independently re-derivable by a third
party from the same recorded inputs bit-for-bit. A deterministic
conformance diff computed and recorded at the moment of the decision has
a narrower job (in-scope or not, against a scope that was already
explicit) but produces something a counterparty can check with a
calculator rather than trust as a judgment call. The two approaches
answer different questions and are not mutually exclusive; this project
implements the deterministic one, which is the piece that offline
verification depends on.

## 6. Architecture and threat model, briefly

A policy gateway evaluates each agent-initiated action against
configured policy, evidence requirements, and (where relevant) a human
approval step, and writes every step of that evaluation as an event into
a hash-chained ledger — each event's hash is computed from its own
content plus the previous event's hash, so the chain is tamper-evident:
altering any recorded event changes every subsequent hash. A signed
receipt is produced for the final decision, bound into that chain. A
dispute packet is a portable slice of that chain, exported with the
receipt, custody, and authentication documents described above.

The threat model the offline verifier is built against: a party holding
a packet should be able to detect, without any communication with the
issuing gateway, (a) any modification to a recorded event's content, (b)
any reordering, insertion, or deletion of events in the chain, (c) a
receipt whose signature does not match the claimed signer key, and (d) a
receipt claiming to be bound to a ledger event that either doesn't exist
in the slice or belongs to a different action. The public repo's test
suite includes explicit tamper tests for each of these categories — a
modified receipt field without a matching signature, and a broken chain
link, both fail loudly with a named reason rather than silently passing.

What the threat model explicitly does not cover: compromise of the
gateway operator's private signing key (key management is out of scope
for the verifier, which only checks that a signature is valid against a
declared public key — comparing that key against the operator's
genuinely published key is the counterparty's responsibility, done out
of band); and correctness of the underlying policy decision itself (the
verifier confirms the record is internally consistent and unaltered, not
that the business decision recorded in it was the right one).

### Verifier auditability

Because the verifier is a single file with no external dependencies
beyond a widely used cryptography library, and because it is published
in a public repository with its own test suite, a counterparty's
security or legal team can review the entire verification logic — every
check it performs and every way it can fail — without needing access to
any part of the private gateway product. This is a deliberate design
constraint, not an incidental one: anything that couldn't be checked
this way was kept out of the offline verifier.

## 7. Regulatory and standards context

The following is offered as context for where this kind of artifact is
relevant, not as a claim of certification, audit, or compliance with any
of the frameworks named. **No certification against any of these
frameworks currently exists for this project.**

- **NAIC Model Bulletin on the Use of AI Systems by Insurers** (adopted
  December 2023): 24 states and the District of Columbia have adopted
  the NAIC Model Bulletin (per the NAIC's own implementation tracker,
  April 2026). Examination is being operationalized now, not just
  drafted: the NAIC's AI Systems Evaluation Tool is in a 12-state pilot
  running March–September 2026, with adoption expected at the NAIC Fall
  2026 National Meeting. The bulletin's expectations around
  documentation, governance, and the ability to explain and evidence an
  AI-influenced decision are directly relevant to what a decision-record
  artifact like this one is built to provide; this document makes no
  claim that any specific deployment satisfies any specific state's
  bulletin requirements.
- **OCC / federal interagency model-risk guidance**: current federal
  guidance in this space is scoped to banks above a substantial
  asset threshold and, as of 2026, does not extend to generative or
  agentic AI specifically — a gap the state insurance regulators'
  bulletins are, by contrast, reaching. This is noted here only to
  observe that the regulatory picture differs materially by sector and
  regulator, not to claim coverage under any federal guidance.
- **ISO/IEC 42001** (AI management systems): an international standard
  for organizational AI governance processes, not a product
  certification. A dispute-packet artifact is a piece of evidence an
  organization operating under such a management system could point to;
  it is not itself an ISO 42001 certification and none is claimed here.
- **MiCA (EU Markets in Crypto-Assets Regulation) record-keeping
  obligations**: MiCA imposes multi-year record-keeping requirements on
  in-scope crypto-asset service providers for the services and
  activities they provide. Where a deployment's payment rail overlaps
  with MiCA's scope, durable, exportable, hash-chained records are
  thematically aligned with that kind of obligation; this is a
  directional observation, not a legal compliance claim, and no
  MiCA-scoped deployment is described here.
- **EU AI Act, Article 12 (record-keeping)**: Article 12 requires
  high-risk AI systems to have logging capabilities enabling traceability
  of the system's functioning throughout its lifecycle. Core high-risk
  obligations under the Act begin applying from August 2026. A
  gateway that already produces a hash-chained, exportable decision
  record for every agent action is, at minimum, **positioned ahead of
  that requirement taking effect** for AI-agent payment actions that
  fall in scope — this document frames it only that way, not as a claim
  of Article 12 conformity, which depends on the full system and use
  case, not on a decision-record format alone.

## 8. What to check yourself

Every claim in Sections 4 through 6 above about the verifier's behavior
can be checked directly:

```bash
git clone <this repository>
cd actaseal-verify
pip install cryptography pytest
pytest -q                                    # full test suite, including tamper tests
python verify.py demo/demo-packet-anchored   # a settled, in-scope decision
python verify.py demo/demo-packet-unanchored # an unsettled, in-scope decision
```

Nothing in this document describes a capability that isn't present in
that repository today, except where marked **(roadmap)**.
