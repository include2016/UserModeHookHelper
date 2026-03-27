---
name: c-cpp-kernel-review
description: 'Review C/C++ and Windows kernel driver changes for correctness, safety, concurrency, API misuse, and regression risk. Use when asked to code review C/C++, review driver code, audit PRs, find bugs, check IRQL/locking/memory issues, or assess security and stability impacts.'
---

# C/C++ Kernel Review

Performs code review for C/C++ and Windows kernel driver code with a findings-first output.

## When to Use This Skill

Use this skill when the user asks to:

- Review C or C++ code changes
- Review Windows kernel driver code (`WDM`, `KMDF`, `minifilter`, callbacks)
- Identify bugs, race conditions, IRQL violations, memory issues, or API misuse
- Assess regression risk before merge/release

## Review Mindset

Primary objective: find defects and risks, not stylistic nits.

Prioritize in this order:

1. Safety and crash risk
2. Security and privilege boundary issues
3. Concurrency and lifetime correctness
4. Behavioral regressions and compatibility risks
5. Test gaps

## Required Inputs

Collect these first:

1. Changed files and patch (`git diff --staged`, `git diff`, or PR diff)
2. Build/test status if available
3. Relevant call paths for changed functions

If the scope is unclear, ask whether to review staged changes, unstaged changes, or both.

## Analysis Workflow

1. Scope changed code
- Identify touched modules, entry points, and critical paths
- Separate user-mode C/C++ from kernel-mode paths

2. Trace impact
- For C/C++, find call sites and affected code paths
- For driver code, verify dispatch paths, callback registration/unregistration, teardown flow

3. Validate correctness invariants
- Null checks, bounds checks, integer overflow/underflow
- Ownership and lifetime for pointers, handles, objects, IRPs, MDLs, and contexts
- Error propagation and cleanup on failure paths

4. Kernel-specific checks
- IRQL correctness (function called at legal IRQL)
- Pageable code/data not accessed at elevated IRQL
- Locking discipline (spinlock/mutex/ERESOURCE ordering and coverage)
- Pool allocations use correct type/tag and are freed on all paths
- Reference counting balance (`ObReference*` / `ObDereference*`)
- APC attach/detach and process/thread context correctness
- User pointer probing/capture and trust boundaries
- Zw/Nt API usage constraints and handle mode assumptions

5. Regression and operability checks
- Backward compatibility behavior
- Logging/telemetry usefulness for triage
- Missing tests for changed behavior and edge cases

## Findings Format (Required)

Return findings first, ordered by severity:

1. `High` - can crash, corrupt memory, or create a security boundary issue
2. `Medium` - functional bug, race, leak, or likely regression
3. `Low` - maintainability issue or minor robustness concern

For each finding include:

- Severity
- File and line reference
- What is wrong
- Why it matters (impact)
- Concrete fix recommendation

Example format:

`[High] controller/UMController/ProcessManager.cpp:142 - Uses user buffer without validating length; can read out of bounds. Validate size before dereference and fail with STATUS_INVALID_PARAMETER.`

## No-Finding Case

If no defects are found, state explicitly:

`No high/medium/low findings identified in reviewed scope.`

Then list residual risks:

- Unreviewed files
- Untested runtime paths
- Missing stress/concurrency/security tests

## C/C++ and Driver Checklist

- Data races around shared state
- Lifetime of stack/heap pointers escaping scope
- Use-after-free and double-free potential
- Lock ordering and deadlock risk
- Error-path cleanup symmetry
- Integer conversion truncation/sign issues
- ABI/packing assumptions in shared structures
- Unsafe string/buffer operations
- Incorrect SAL assumptions or contract drift
- Driver unload/teardown correctness

## Tooling Guidance

Prefer semantic symbol tools over text grep for C/C++ impact analysis.
When available, use symbol references/call hierarchy to prove reachability before claiming impact.

## Output Structure

1. Findings (ordered by severity)
2. Open questions/assumptions
3. Brief change summary
4. Test gaps and suggested tests
