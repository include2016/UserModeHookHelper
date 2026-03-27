---
name: generate-commit-message
description: 'Generate high-quality git commit messages from code changes. Use when asked to write commit messages, summarize staged/unstaged diffs, or produce conventional commits from current repository modifications.'
---

# Generate Commit Message

Creates clear, accurate commit messages directly from the repository diff.

## When to Use This Skill

Use this skill when the user asks for:

- A commit message based on current code changes
- A conventional commit message
- Multiple commit message options for the same diff
- A commit title and explanatory body for non-trivial changes

## Inputs To Collect

Before writing a message, inspect changes in this order:

1. `git status --short`
2. `git diff --staged` (preferred if staged changes exist)
3. `git diff` (if unstaged changes are relevant)
4. `git log -n 5 --pretty=format:"%h %s"` (optional style check)

If the user says "staged only", ignore unstaged changes.
If the user says "all changes", include both staged and unstaged diffs.

## Commit Message Rules

1. Subject line:
- Max 72 characters
- Imperative mood ("add", "fix", "refactor")
- No trailing period

2. Body (include when useful):
- Wrap around 72-100 chars per line
- Explain why the change was made and notable behavior impacts
- Mention risk areas or migration notes when applicable

3. Accuracy:
- Do not claim changes not present in the diff
- Mention key files/components touched when helpful

## Conventional Commit Mode

When user asks for conventional commits, use this pattern:

`<type>(<scope>): <subject>`

Common types:

- `feat`: new functionality
- `fix`: bug fix
- `refactor`: internal change without behavior change
- `perf`: performance improvement
- `docs`: documentation change
- `test`: testing changes
- `chore`: maintenance/tooling

If scope is unclear, omit it.

## Output Format

Default output:

1. `Primary message` (best choice)
2. `Alternative 1`
3. `Alternative 2`

If user asks for "just one", return only one message.
If user asks for "title only", return only the subject line.

## Quality Checklist

Before responding, verify:

- Message reflects actual diff content
- Subject is concise and imperative
- Type/scope (if used) matches the change
- Body explains impact for complex edits
