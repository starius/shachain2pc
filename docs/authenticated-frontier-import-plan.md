# Authenticated Frontier Import / Relabel Plan

This document records an optional future cryptographic optimization for the
daemon frontier. It is not implemented and is no longer on the daemon critical
path. Live per-channel sessions already provide incremental precompute while
both daemons stay up. Import/relabel would only let a daemon turn a persisted
authenticated node into a fresh-session AG2PC input after restart or session
teardown, avoiding re-warm from the seed.

## Current State

Phase A persists frontier nodes as:

- `lambda`;
- one local IT-MAC bundle per bit: `mac`, `key`;
- immutable public/local binding metadata.

It deliberately does not persist garbled labels. Labels are fresh session-local
randomness. Persisted nodes are therefore revealable after restart, because
public reveal only needs the authenticated value, but they are not usable as
inputs to a new garbled computation.

Current precompute starts from the seed in one live AG2PC session, carries
labels in memory, and stores label-stripped exact target leaves. While that live
session remains up, later precompute calls reuse the labeled in-memory frontier
and do not rederive shared prefixes. After restart or session teardown, the
daemon starts a fresh session and re-warms from the seed rather than importing a
persisted node as a computation parent.

## Desired Primitive

`import_authenticated_node(session, node) -> Ag2pcSecureWires`

Inputs:

- both parties' persisted authenticated shares of the same node;
- same fixed per-channel Delta;
- same immutable node binding and security parameters;
- a fresh AG2PC session with fresh OT/preprocessing/garbling randomness.

Output:

- a fresh-session `Ag2pcSecureWires` for the same secret value;
- same `lambda` and IT-MAC relation, or a safely refreshed equivalent;
- new Alice `label0` / Bob `eval_label` consistent with the imported wire;
- no cleartext shachain intermediate revealed to either party.

## Candidate Label Relabel Step

If the persisted MAC/lambda state is accepted as valid, the remaining task is
to attach fresh session labels to the same authenticated value. This is not a
one-message label send.

1. Both parties validate the node binding:
   channel id, peer identity, protocol version, circuit digest, Delta
   derivation version, node mask/depth, `ssp_target`, and lifetime cap.
2. Alice samples a fresh `label0[i]` for every imported bit.
3. Bob must receive the active label for the wire's external value
   `x[i] = lambda[i] xor mac_lsb_A[i] xor mac_lsb_B[i]`.
4. Neither party knows `x[i]` alone, and directly exchanging the MAC-LSB
   shares would reveal the imported secret. Therefore the label transfer must
   obliviously combine both value shares, likely using an authenticated-input or
   OT-style subprotocol, while binding the result to the accepted MAC state.
5. The imported wires have fresh labels for the current session only after that
   oblivious transfer/import step succeeds.

The tempting shortcut `label0[i] xor (lambda[i] * Delta)` is insufficient:
`lambda` is only the mask share, not the external bit. It would either place the
wrong active label or require revealing the missing MAC-LSB share. This protocol
must mirror the security of `process_inputs` without re-inputting or opening the
cleartext value.

## Open Security Question

The hard parts are the unopened MAC-consistency check and the oblivious active
label transfer. The protocol must prove that both parties can use the persisted
authenticated value as a new-session input without opening the secret or
accepting a maliciously substituted node.

The protocol needs a MAC-consistency/import check that:

- binds both parties to the same persisted node and immutable context;
- does not exchange the MAC LSB shares in a way that reveals
  `x = lambda xor mac_lsb_A xor mac_lsb_B`;
- aborts if either party presents a malformed or mismatched authenticated node;
- composes with the existing AG2PC correct-or-abort checks;
- preserves forward secrecy: one daemon compromise learns only that party's
  shares, not unrevealed shachain values.

The current public reveal check is not enough for import because it reveals the
value. A direct exchange of MAC LSB shares would also reveal the value.

## Review Questions

1. Is a separate import MAC check required, or is it sufficient to bind the node
   digest and rely on later AG2PC MAC/equality checks to abort before output?
2. If a separate check is required, can it be implemented as a standard SPDZ-like
   MAC check over unopened authenticated bits, with fresh random coefficients
   derived after commitment to the imported node transcript?
3. Does keeping the same `lambda` across sessions leak anything when labels and
   all MPC randomness are fresh?
4. Should import refresh the authenticated representation itself, or only attach
   fresh labels to the existing Delta-bound representation?
5. What exact transcript fields must feed the import digest so stale nodes,
   downgraded security parameters, wrong peer identity, and wrong circuit
   versions fail closed?

## Required Tests Before Implementation Is Accepted

- Unit test: importing a persisted valid node and then applying one H matches a
  single-session reference path.
- Restart integration test: precompute `I=1`, restart, import `I=1`, extend to
  `I=3`, reveal, and match the reference.
- Tamper tests:
  - flip `lambda`;
  - flip `mac`;
  - flip `key`;
  - swap node binding metadata;
  - use different `ssp_target` or lifetime cap.
- Each tamper must abort before any cleartext output is produced.
- Regression test that serialized nodes still contain no labels.

## Non-Goals

- Do not derive or reuse OT, garbling, leaky-AND, preprocessing, or label
  randomness from the master secret.
- Do not store cleartext unrevealed shachain values.
- Do not make the DB a reveal-frontier authority. The caller-provided
  `expected_next_index` remains mandatory for non-local reveals.

## Implementation Gate

This protocol is cryptographic, not plumbing. It should not be implemented for
the funds path until the import MAC-consistency argument is reviewed by a human
MPC cryptographer. The current daemon design does not need it for correctness
or ordinary incremental precompute: it persists exact target leaves for fast
reveal, keeps live labels in RAM while the session is up, and re-warms from the
seed after restart.
