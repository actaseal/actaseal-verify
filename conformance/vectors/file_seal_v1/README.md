# file_seal_v1 conformance vectors

Seals written by ActaSeal's `actaseal seal` (format `actaseal.file-seal.v1`) over the
files in `files/`, for `verify_seal.py` and any other implementation to check against.

- `seal_day1.json`, `seal_day2.json`: signed, RFC 3161-timestamped, and chained
  (day 2's `previous_seal_sha256` is day 1's seal hash). Day 2's label is non-ASCII on
  purpose: the seal hash is over UTF-8 canonical JSON, not ASCII-escaped JSON.
- `expected.json`: the verification results ActaSeal's own verifier produced, with the
  signer's public key and the timestamp's time.
- `test_tsa_ca.pem`: the CA of a throwaway test TSA made only for these vectors. Never
  trust it for real seals.

The Ed25519 key is derived from a fixed test string and is public; it is for these
vectors only.
