# Contributing

This repository is maintained as an Orizon IT product engineering project.

## Workflow

Use the following flow:

```text
issue -> branch -> implementation -> local validation -> pull request -> review -> merge
```

Recommended branch names:

- `feature/<short-description>`
- `fix/<short-description>`
- `docs/<short-description>`
- `refactor/<short-description>`

## Commit convention

Use short Conventional Commit-style messages:

- `feat:` new capability
- `fix:` defect correction
- `docs:` documentation
- `test:` test or validation
- `refactor:` internal change without intended behavior change
- `chore:` repository/tooling maintenance
- `security:` security hardening

## Collector requirements

A collector change should:

1. remain read-only unless a requirement explicitly says otherwise;
2. never collect passwords, tokens, private keys or secrets;
3. keep output deterministic and structured where possible;
4. record collection failures as errors/limitations instead of silently hiding them;
5. preserve documented compatibility;
6. produce valid JSON;
7. avoid environment-specific hard-coded values;
8. document new fields or behavioral changes;
9. update the changelog when relevant.

## Pull requests

A PR should state:

- what changed;
- why it changed;
- platforms/versions tested;
- test evidence;
- output/schema impact;
- security impact;
- rollback considerations when applicable.

Do not include real customer output in issues or pull requests.
