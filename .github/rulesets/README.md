# Repository rulesets

Exported copies of the rulesets of this repository, so they are versioned and reviewable.

GitHub does not read these files. The live rulesets are in **Settings → Rules → Rulesets**. When you change a ruleset there, export it again and update the file here in the same pull request. To set up a new repository with the same rules, use **Import a ruleset** with one of these files.

| File | Ruleset |
|---|---|
| [main.json](main.json) | Protects the default branch: pull requests only, squash merges, linear history, merge queue |
| [release-tags.json](release-tags.json) | Protects `v*` tags: only admins create them; no update, deletion, or force push |
