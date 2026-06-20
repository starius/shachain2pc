# Rust sync plan

This older planning entry has been superseded by
[`rust-ag2pc-transition-plan.md`](rust-ag2pc-transition-plan.md).

The remaining sync work is no longer the shachain/cache application layer. Rust
already has the current recursive-tile cache shape. The blocker for current
C++/Rust cross-mode is the MPC backend: current C++ uses the rewritten
`AG2PCSession`/SoftSpoken backend, while Rust still uses the older WRK17/C2PC
backend.

Use the new transition plan for implementation and review. It explicitly includes
removing the old Rust backend from active code once the new backend is in place.
