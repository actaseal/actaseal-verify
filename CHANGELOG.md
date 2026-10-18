# Changelog

The version history as it is, including where the numbering does not
line up. Nothing here has been renumbered or retagged.

## How the numbers came to be

- The package was first uploaded to PyPI as version `1.0.0` on
  2026-07-20, before this repository had any tag. In git there is
  no `v1.0.0` tag.
- Git tags then started lower, at `v0.1.0`, and counted up to `v0.2.2`.
  Throughout that time the package metadata in the repository still said
  `1.0.0`.
- On 2026-10-12 the repository's package metadata was brought in line
  with what PyPI already had: the next version after PyPI's `1.0.0` is
  `1.0.1`, and from there the tag and the package version are the same
  number.

So `v0.2.2` and `v1.0.1` are consecutive, made the same day, and
`1.0.x` is later than every `0.x` tag.

## 1.0.2

Not yet tagged or published. See
[docs/release-notes/1.0.2.md](docs/release-notes/1.0.2.md).

- `verify.py --checkpoint HEX`: a keyless check for full packets.
- `verify.py` refuses small-order, mixed-order and non-canonical Ed25519 public keys and signature R values by itself, before the cryptography library is asked.
- Source comments and help text describe each check in this
  repository's own terms.
- Conformance: new `packet_checkpoint` vectors; the pinned-digest vector
  regenerated.
- `CITATION.cff`; the README installs from PyPI and cites the concept
  DOI.

## Tags and where each was published

| Git tag | Date | GitHub release | PyPI `actaseal-verify` | Zenodo |
|---|---|---|---|---|
| (none) | 2026-07-20 | no | `1.0.0` | no |
| `v0.1.0` | 2026-09-21 | yes | no | no |
| `v0.2.0` | 2026-10-05 | no | no | no |
| `v0.2.1` | 2026-10-05 | no | no | no |
| `v0.2.2` | 2026-10-12 | yes | no | 10.5281/zenodo.23309308 |
| `v1.0.1` | 2026-10-12 | yes | `1.0.1` | 10.5281/zenodo.23309816 |

All archived versions: concept DOI 10.5281/zenodo.23309307.

## What each tag was

Taken from the commits between tags.

- `v1.0.1`: package metadata renamed to `actaseal-verify` and numbered
  to follow PyPI; README citation. No verifier change from `v0.2.2`.
- `v0.2.2`: receipt key binding and `--receipt-public-key`;
  `--receipt-keyring` (a receipt signed under a rotated-out key told
  apart from a forged one); `-h`/`--help`; browser verifier key
  pinning; Zenodo metadata. The first archived version.
- `v0.2.1`: the structured result of `verify_receipt.py` gained
  `outcome`, `exit_code` and `failed_checks`.
- `v0.2.0`: browser verifier; a `.zip` packet accepted directly;
  archive-export mode detected automatically; `verify_seal.py`;
  structured result for `verify_receipt.py` (`--emit-result`);
  deterministic conformance vectors.
- `v0.1.0`: first tagged offline verifier, with demo packets,
  conformance vectors and the keyless mode of `verify_receipt.py`.
