# Design records

Architecture decision records (ADRs) for pgroles. An ADR records a decision,
not a design or a task list: the problem and constraints, the chosen approach,
why it won, the rejected alternatives, and the consequences — including
operational risks and follow-up work — and it distinguishes the intended
steady state from the migration path.

Specification prose belongs in `docs/src/pages/docs/`; ADRs must stay legible
without access to the issue tracker. Number files sequentially
(`adr-NNN-<topic>.md`) and keep the status line (`Proposed`, `Accepted`,
`Superseded by ADR-NNN`) current. An accepted ADR may be updated in place as
more information becomes available — corrected facts, measured numbers,
executed follow-ups; a *reversal* of the decision is a new ADR that names what
it supersedes.

## Index

- [ADR-001: PostgresPolicyCandidate API](adr-001-candidate-api.md) — bound the
  shared policy-content schema instead of forking it; whole-spec CEL
  immutability; candidate ownership, planning context, overlay-overlap rules,
  and the execution preflight a preview runs with its parent's settings.
