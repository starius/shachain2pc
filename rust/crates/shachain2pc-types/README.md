# shachain2pc-types

## Role

This crate owns the small domain types shared by the rest of the Rust
implementation. It intentionally has no project-local dependencies, so all
other crates can depend on it without creating dependency cycles.

## Place In The Stack

`shachain2pc-types` is the bottom layer for common constants and parsing:
party roles, 48-bit shachain indices, and 32-byte secret values. It does not
know about circuits, transports, MPC frames, or daemon state.

## Public Interface

- `Role`: the two MPC parties, encoded as party ids `1` and `2`.
- `Index48`: checked 48-bit shachain indices with hex parsing/formatting.
- `Value32`: 32-byte values with hex and MSB-first bit conversion helpers.
- `VALUE_BYTES`, `VALUE_BITS`, `INDEX_BITS`, and `MAX_INDEX`.

## Invariants

- `Index48` must reject values outside the 48-bit shachain space.
- `Value32` bit conversion is MSB-first because the circuits and reference
  shachain logic use that ordering.
- Keep this crate dependency-free unless there is a very strong reason.

