# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-11-21

## Context

NilPerit stores data that may need to be read decades from now, possibly by people who never talked to the original authors. Design choices (encryption, layout, what is truth and what is cache) have long-lived consequences. Without a record of *why* something was chosen, later contributors either repeat old discussions or change things without understanding the trade-offs.

## Decision

We keep architecture decision records in `docs/decisions/`, one decision per file, in plain English. The normative format lives in `docs/format.md` (Simplified Technical English plus RFC 2119 keywords). Terms are defined once in `docs/glossary.md`.

A pull request that changes the format also updates `format.md` and, if it changes a decision, adds a new ADR.

## Consequences

- Design history stays traceable and reviewable.
- Specs and code are changed together, so they do not drift.
- Writing an ADR is a small cost per significant decision.

## Alternatives considered

- **Wiki:** drifts from the code, not versioned with it, not reviewable in PRs.
- **Design notes only:** fine for a first session, but they mix decisions, rationale and open questions.
