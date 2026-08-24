# Boule Community mock scenario

This fixture tests protocol mechanics around an Erdős 686-themed case. It does
not test the mathematics and does not contact Codex, Claude, GitHub,
Conjectures.io, Bittensor, or a wallet.

## Scenario

1. Session A records `BLOCKED`: the supplied continuation README exists, but
   the advertised reproducibility bundle is absent.
2. Session B records a synthetic `ADVANCE` that explicitly uses A.
3. Session C records both knowledge accesses, integrates B, and therefore
   transitively depends on A.
4. A first candidate declares B and C but omits A. Its synthetic technical
   verifier says `pass`, while Boule correctly refuses to seal attribution.
5. The corrected manifest declares A, B, and C. Three sealed reviewers allocate
   2,500 / 3,000 / 4,500 basis points.
6. A bounty of 1,000,003 fictional Alpha-rao is divided exactly and every
   positive mock leg reaches its simulated terminal state.

Each session boundary writes the ledger to JSONL, discards live protocol state,
reads the file, verifies the hash chain and signatures, and reconstructs the
frontier before continuing.

## Run

```bash
uv run python -m boule community-demo --output boule-community-mock
uv run python -m boule verify-community-ledger \
  boule-community-mock/ledger.jsonl --require-allocation --require-mock-paid
uv run python -m boule community-agent-prompt \
  boule-community-mock/ledger.jsonl
```

The output directory is intentionally required to be new so a previous
transcript cannot be silently overwritten.
