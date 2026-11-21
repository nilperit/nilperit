# 0009. Sources as account plus selection, with priority

- Status: Accepted
- Date: 2026-11-21

## Context

Not all data is equally important: a banking folder matters more than a spam folder. When time or space is short ("if I have to run"), the most critical data must exist first.

## Decision

- A **source** is a connector account plus a selection, for example `gmail-banking` (label Banking), `gmail-spam`, or specific folders of a file store.
- Each source has its own snapshots, journal, retention rules and a **priority**.
- Priority drives: the order of synchronisation, the order of ingest within a run, the order of replica synchronisation (for example when a USB stick is inserted), and the order of cleanup under storage pressure.
- Packs do not mix priority classes where avoidable. Replica sync follows snapshot references, not pack lists, so deduplication across priorities never leaves a critical item incomplete.

## Consequences

- Overlapping sources cost nothing extra, thanks to deduplication.
- Critical data reaches every target first.
- Configuration is slightly richer than "one account = one backup".

## Alternatives considered

- **One snapshot across all sources:** simpler, but no independent schedules, retention or priorities.
