#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Byte-equality gate for the vendored canon artifacts. Each file under contracts/
# that is copied byte-identical from the architecture canon (see VENDORED.md) must
# still hash to the git blob OID recorded in VENDORED.md. A silent local mutation
# of a vendored contract — an "improvement", a merge artifact, a hand-edit — reds
# this gate, so the copy cannot drift from what its provenance record claims.
#
# This checks LOCAL SELF-CONSISTENCY (file == recorded OID), not provenance
# against canon: provenance is established firsthand at vendoring time and written
# into VENDORED.md; CI has no canon checkout. The two are complementary — the
# recorded OID is only trustworthy because it was verified against canon when
# written, and this gate keeps the file matching that record thereafter.
#
# A git blob OID is sha1("blob <len>\0" + bytes), which is exactly what
# `git hash-object` computes; we reproduce it without shelling out so the gate
# runs even in a bare checkout.
#
# Two-sided: `--self-test` mutates a copy of each vendored file and asserts the
# check goes RED, and asserts the shipped files pass.
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The vendored files and their expected git blob OIDs, mirroring the "Vendored as
# a file" table in VENDORED.md. Keep this list in lockstep with that table.
#
# The values are git blob OIDs — public, mechanical provenance hashes (sha1 of
# "blob <len>\0<bytes>", the git object id), NOT secrets. They are the SAME OIDs
# published in VENDORED.md and re-derivable with `git hash-object`. The
# `gitleaks:allow` markers below suppress the generic-api-key rule's false
# positive on the 40-hex OID literals; they silence nothing else (the sk-ocu-
# rule and every other file are unaffected).
VENDORED = {
    "contracts/mcp/2025-06-18/ocu-constraints.schema.json": "23b28bda5acf347f925592701f770f39aa1b97ee",  # gitleaks:allow (git blob OID, not a secret)
    "contracts/audit/audit-fanin.asyncapi.yaml": "6beb0cab568c44572f0eec756f8028335cda2288",  # gitleaks:allow (git blob OID, not a secret)
    "contracts/proto/ocu/control/session/v1/session_setup.proto": "3ebd2c93dc303a4dd47b39c5ef81f3cde959b73b",  # gitleaks:allow (git blob OID, not a secret)
    "contracts/mcp/mcp-key-set.schema.json": "25329b0f572b049ed593d5bc7fe14f74980b0091",  # gitleaks:allow (git blob OID, not a secret)
}


def fail(msg):
    print(f"::error::vendored-check: {msg}", file=sys.stderr)
    sys.exit(1)


def git_blob_oid(data: bytes) -> str:
    """Compute the git blob OID of raw bytes: sha1('blob <len>\\0' + data).

    SHA-1 is REQUIRED here: a git blob object id IS sha1("blob <len>\\0<bytes>")
    by git's on-disk format. This is not a security hash choice — it reproduces
    `git hash-object` so the gate can compare a vendored file to the blob OID
    recorded in VENDORED.md without shelling out. Not used for any integrity or
    authentication decision about untrusted data.
    """
    header = b"blob " + str(len(data)).encode() + b"\0"
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return hashlib.sha1(header + data).hexdigest()  # git blob OID format (not a security hash)


def oid_of_file(path: str) -> str:
    abspath = os.path.join(ROOT, path)
    if not os.path.isfile(abspath):
        fail(f"vendored file missing at {path} (fail-closed)")
    with open(abspath, "rb") as f:
        return git_blob_oid(f.read())


def check_all():
    for path, want in VENDORED.items():
        got = oid_of_file(path)
        if got != want:
            fail(
                f"{path} has blob OID {got}, expected {want} (VENDORED.md). "
                f"The vendored copy drifted from its recorded provenance; re-vendor "
                f"byte-identical from canon or update VENDORED.md with a verified OID."
            )
    print(f"vendored-check: all {len(VENDORED)} vendored artifacts match their recorded blob OIDs")


def self_test():
    # Every shipped vendored file must currently pass.
    for path, want in VENDORED.items():
        got = oid_of_file(path)
        if got != want:
            print(f"::error::self-test: shipped {path} does not match recorded OID {want} (got {got})", file=sys.stderr)
            sys.exit(1)

    # Neuter: mutating any vendored file's bytes must change its OID (the gate would
    # go RED). We compute the OID of the file with one byte appended and assert it
    # differs from the recorded OID — i.e. the check is sensitive to a mutation.
    for path, want in VENDORED.items():
        abspath = os.path.join(ROOT, path)
        with open(abspath, "rb") as f:
            mutated = f.read() + b"\n// tamper\n"
        if git_blob_oid(mutated) == want:
            print(f"::error::self-test: a mutation of {path} did NOT change its blob OID (gate is a no-op)", file=sys.stderr)
            sys.exit(1)

    print("vendored-check self-test: shipped files match; a mutation reds the gate (RED-when-tampered, GREEN-as-shipped)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
    else:
        check_all()
