# Git Log — Network Intrusion Detection & Anomaly Intelligence

## 1. Purpose

This document maintains a human-readable record of meaningful Git commits made during project development.

It supplements the actual Git history and provides context about important changes.

The repository's Git history remains the authoritative source for commits.

## 2. Git Rules

- Record only commits that actually exist.
- Never invent commit hashes, messages, dates, or branches.
- Do not record uncommitted changes as commits.
- Do not create commits automatically unless authorized.
- Use meaningful commit messages.
- Keep datasets, model binaries, secrets, virtual environments, and temporary files out of version control.
- Do not overwrite existing Git history.
- Verify commit information using Git before adding an entry.

## 3. Recommended Commit Message Convention

Use the following format:

`<type>: <short description>`

Recommended types:

| Type | Purpose |
|---|---|
| `feat` | New functionality |
| `fix` | Bug fixes |
| `refactor` | Code restructuring without intended behavior changes |
| `docs` | Documentation changes |
| `test` | Adding or modifying tests |
| `chore` | Maintenance and configuration |
| `data` | Dataset or data-pipeline changes |
| `model` | Machine learning model changes |
| `style` | Formatting and style changes |

Examples:

- `chore: establish project architecture`
- `feat: implement CIC-IDS2017 data ingestion`
- `feat: add network flow preprocessing pipeline`
- `model: add binary intrusion classification baseline`
- `fix: handle infinite flow-rate values`
- `test: add preprocessing validation tests`
- `docs: document model evaluation methodology`

These are examples only. Do not record them as actual commits unless they have been made.

## 4. Commit Entry Format

Append new entries using this structure.

---

### Commit [NUMBER] — [COMMIT MESSAGE]

**Date:** YYYY-MM-DD  
**Commit Hash:** `[actual short or full hash]`  
**Branch:** `[actual branch name]`  
**Type:** feat / fix / refactor / docs / test / chore / data / model / style

#### Summary

Briefly explain what the commit introduced or changed.

#### Important Changes

- Change 1.
- Change 2.
- Change 3.

#### Files or Components Affected

- `path/to/file.py`
- `path/to/directory/`

#### Validation

Describe the tests or checks performed before the commit.

#### Related Development Phase

Phase XX — [Phase Name]

---

## 5. Recorded Commit History

No project commits have been recorded in this document yet.

Before adding the first entry, inspect the repository's actual Git history and determine whether existing commits need to be documented.

Do not assume this document represents the complete Git history.