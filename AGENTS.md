# Microsoft Git Fork - Development Guide

## Background and History

### Fork Hierarchy

Microsoft Git is a fork of Git for Windows, which is itself a fork of
upstream Git:

```
Git (upstream) -> Git for Windows -> Microsoft Git
```

**Git for Windows** exists because upstream Git has limited Windows support.
Git for Windows provides the necessary adaptations to make Git work well on
Windows.

**Microsoft Git** builds on Git for Windows to add features specifically for
large monorepos, particularly those hosted on Azure DevOps. Unlike Git for
Windows, Microsoft Git also ships macOS and Linux packages.

### The VFSforGit Era

Microsoft Git was originally created to support
[VFSforGit](https://github.com/microsoft/VFSforGit) (originally called "GVFS",
Git Virtual File System, renamed because it clashed with the GNOME Virtual File
System). VFSforGit uses a virtual file system driver to present a
fully-populated working directory while only materializing files on demand.

However, the virtual file system approach proved to be a dead end. The
functionality required for macOS support had been removed from the targeted
macOS versions, making it impossible to extend VFSforGit to that platform.

### The Scalar Era

As a consequence of VFSforGit's limitations, the **Scalar** project was
created. Originally [a .NET application](https://github.com/microsoft/scalar)
and a close fork of VFSforGit, Scalar takes a different approach that does not
require a virtual file system. Instead, it relies on:

- **Partial clone** - Fetching only needed objects from the server
- **Sparse checkout (cone mode)** - Only checking out a subset of files
- **Sparse index** - Optimizing the index for sparse checkouts

These features were developed and tested in the Microsoft Git fork, then
painstakingly upstreamed to the Git project over time. Eventually, Scalar
itself was ported from .NET to plain C and also upstreamed - Scalar is now
part of upstream Git.

### Why the Fork Still Exists

Despite successful upstreaming of many features, the Microsoft Git fork
continues to exist for two key reasons:

1. **VFSforGit**: The VFSforGit program is still in active use by a project
   whose repository shape is not supported by cone-mode sparse checkouts.

2. **Test bed for new features**: The upstream Git project's contribution
   process is slow and rigorous. Microsoft Git serves as a place to develop,
   test, and spike features before undertaking the lengthy upstream
   contribution process.

2. **GVFS Protocol support**: Historically, Azure DevOps did not support
   Git's partial clone protocol. The GVFS protocol (implemented via
   `gvfs-helper`) allows Microsoft Git to emulate partial clone functionality
   when working with Azure Repos. This is the only Git fork that supports
   the GVFS protocol. Scalar clones, however, run more efficiently using
   that GVFS protocol than the partial clone feature of upstream Git.

### GVFS Protocol Advantages

The GVFS protocol is more efficient than Git's native partial clone in
several ways:

- **Individual commit fetching**: Git's partial clone cannot fetch a single
  commit without also fetching its entire parent chain (unless it's a root
  commit). The GVFS protocol allows fetching individual commits or arbitrary
  batches of commits.
- **CI optimization**: This efficiency is particularly valuable in CI
  scenarios.

### Limitations

The GVFS protocol only works with Git forges that implement it. Currently,
**Azure Repos (Azure DevOps)** is the only forge that supports this protocol.
This is unlikely to change, ever. This Azure-specific nature means the GVFS
helper functionality will never be upstreamed to Git.

## Overview

This document provides guidance for developing and debugging in the
Microsoft Git fork.

## Working Style

The most effective way to drive AI-assisted work on this codebase is
not through fancy prompts but through a disciplined, iterative workflow
that keeps the human firmly in the loop. As the agent, your default
mode of operation should be to slow down, surface what you are about
to do, and let the user steer.

### Start by Understanding

Before proposing any changes, take time to understand the relevant
slice of the codebase. Answer concrete questions:

- Where are the important functions for this area?
- How does control flow through the code base for the relevant
  scenario?
- Where are the existing tests, and what do they cover?

When you do not yet know the answers, do not start editing code. Read
first. Use `git grep`, `git log -L`, and the rest of the tooling
described elsewhere in this document to build a real understanding.
If you cannot find something, ask the user; do not guess.

Surface what you have learned in your response so the user can correct
misunderstandings before they become bad code.

### Plan Before Implementing

For anything beyond a trivial one-line change, produce a written plan
before touching code. The plan must be commit-by-commit:

- Each entry in the plan corresponds to one commit, which should be a
  coherent, independently reviewable unit (one logical change).
- For each commit, state the title, the intent, and the files or
  areas that will change.
- Include concrete code sketches for non-obvious changes. The user
  will review the snippets carefully; a few lines of pseudo-code are
  worth more than a paragraph of prose.

Save the plan where the user can edit it (e.g. in the session
workspace) and wait for approval or amendments before starting
implementation. The plan is the contract; do not deviate from it
without checking back in.

### Implement One Commit at a Time

Execute the plan one commit at a time. After each commit:

1. Stop. Do not start the next commit on your own initiative.
2. Surface what you did: the commit title, the diff, and anything
   surprising you ran into.
3. Wait for the user to review and either approve, request changes,
   or tell you to move on.

Resist the temptation to "knock out a few related commits while the
context is fresh". The user wants to review each commit before the
next one builds on it; bundling work together defeats this.

### Expect Heavy Review and Iteration

Assume that every commit will be reviewed in detail and that some
will need adjustment. The user will frequently:

- Drive the incremental rebase themselves (autosquash, reword,
  rearrange) rather than delegating it.
- Then prompt you to make specific follow-up edits on top of the
  rewritten history.

When you receive such a prompt, do not redo the rebase or rewrite
unrelated history. Make the requested changes as `fixup!` commits
(or direct edits to the working tree if the user says so) and let
the user fold them in.

This human-in-the-loop iteration is the point. Optimize for making
each round of review fast and surgical.

## Repository Structure

### Key Custom Components

| Component            | Files                          | Purpose             |
|----------------------|--------------------------------|---------------------|
| GVFS Helper          | `gvfs-helper*.c`               | GVFS Protocol       |
| Virtual Filesystem   | `virtualfilesystem.c`          | Sparse working dir  |
| Scalar               | `scalar.c`                     | Monorepo management |
| Status Serialization | `wt-status-serialize.c`        | Large repo perf     |

### Branch Naming Patterns

Based on actual repository usage:

- `vfs-X.Y.Z` - Release branches based on upstream Git version X.Y.Z
- The latest release corresponds to a commit on such a `vfs-X.Y.Z` branch.
- The branch corresponding to the latest release is the default branch.
- `tentative/vfs-X.Y.Z` - Work-in-progress rebases onto new upstream versions.
  Once "merged" (or, pushed to fast-forward), the corresponding `vfs-X.Y.Z`
  branch will become the new default branch.
- Feature branches use descriptive topic names (e.g., `prefetch-since`,
  `scalar-gvfs-verb`, `fix-mimalloc-crash-in-post-command`), targeting the
  default branch (potentially needing porting to in-flight `tentative/*`
  branches).

## Building and Testing

### Build

```bash
make -j$(nproc)
```

On Windows (in a Git for Windows SDK shell):

```bash
make -j15
```

### Run Specific Tests

```bash
cd t && sh t5793-gvfs-helper-integration.sh      # Run normally
cd t && sh t5793-gvfs-helper-integration.sh -v   # Verbose
cd t && sh t5793-gvfs-helper-integration.sh -ivx # verbose, trace, fail-fast
```

Some tests are expensive and skipped by default. When a test exits immediately
with "skip all", check the test script header for `test_bool_env GIT_TEST_*`
to find which environment variable enables it.

### GVFS Test Files

| File                                 | Purpose                       |
|--------------------------------------|-------------------------------|
| `t/t5790-gvfs-helper-basic.sh`       | Basic GVFS helper tests       |
| `t/t5791-gvfs-helper-errors.sh`      | Error handling tests          |
| `t/t5792-gvfs-helper-auth.sh`        | Authentication tests          |
| `t/t5793-gvfs-helper-integration.sh` | Integration with Git commands |
| `t/t5794-gvfs-helper-packfiles.sh`   | Packfile handling tests       |
| `t/t5795-gvfs-helper-verb-cache.sh`  | Cache server verb tests       |
| `t/lib-gvfs-helper.sh`               | Shared test helper functions  |

## Git Source Code Structure

This section provides a bird's eye view of Git's source code layout. For
more details, see "A birds-eye view of Git's source code" in
`Documentation/user-manual.adoc`.

### Key Directories

| Directory        | Purpose                                            |
|------------------|----------------------------------------------------|
| `builtin/`       | Built-in command implementations (`cmd_<name>()`)  |
| `xdiff/`         | Low-level diff algorithms (libxdiff)               |
| `t/`             | Test suite (shell scripts, helpers, libraries)     |
| `Documentation/` | Man pages, guides, technical docs (AsciiDoc)       |
| `contrib/`       | Optional extras, not part of core Git              |
| `compat/`        | Platform compatibility shims                       |
| `refs/`          | Reference backends (files, reftable)               |
| `reftable/`      | Reftable format implementation                     |

### Built-in Commands

Built-in commands are implemented in `builtin/<name>.c` with a function
`cmd_<name>()`. To add a new built-in:

1. Create `builtin/<name>.c` implementing `cmd_<name>()`
2. Add entry to the `commands[]` array in `git.c`:
   ```c
   { "<name>", cmd_<name>, RUN_SETUP },
   ```
3. Add to `BUILTIN_OBJS` in `Makefile`
4. Add to `command-list.txt` with appropriate category
5. Run `make check-builtins` to verify consistency

### Object Data Model

Git stores four types of objects, defined in `object.h`:

```c
enum object_type {
    OBJ_COMMIT = 1,  /* Points to tree, has parent commits, metadata */
    OBJ_TREE = 2,    /* Directory listing: names -> blob/tree OIDs   */
    OBJ_BLOB = 3,    /* File contents                                */
    OBJ_TAG = 4,     /* Annotated tag pointing to another object     */
};
```

Objects are addressed by their SHA (OID) and stored in the Object Database.

### Object Database (ODB)

The ODB is defined in `odb.h` and implemented in `odb.c`:

- **`struct object_database`**: Top-level container, owned by a repository
  - `sources`: Linked list of `odb_source` (primary + alternates)
  - `replace_map`: Object replacements (see `git-replace(1)`)
  - `commit_graph`: Commit-graph cache for faster traversal

- **`struct odb_source`**: A single object store location
  - `path`: Directory (e.g., `.git/objects` or an alternate)
  - `loose`: Loose object cache
  - `packfiles`: Packfile store (idx + pack files)

Key functions:
- `odb_read_object()`: Read an object by OID
- `odb_write_object()`: Write an object, returns OID
- `odb_read_object_info()`: Get object type/size without reading content

### Documentation

Documentation lives in `Documentation/` as AsciiDoc (`.adoc`) files:

- `git-<cmd>.adoc` - Man pages for commands
- `config/<name>.adoc` - Config option documentation (included by others)
- `technical/` - Technical specifications and internals

To build documentation:
```bash
make -C Documentation html   # Build HTML docs
make -C Documentation man    # Build man pages
```

To add documentation for a new config option, add it to the appropriate
file in `Documentation/config/`. These are included by other docs.

To lint documentation:
```bash
make -C Documentation lint-docs
```

## GVFS Architecture

### Object Fetching Paths

Two mechanisms exist for fetching missing objects:

1. **Batch Queue** (efficient): `gh_client__queue_oid()` ->
   `gh_client__drain_queue()`
   - Collects multiple OIDs and fetches via single POST request
   - Used by promisor-remote code path

2. **Immediate Fetch** (fallback): `gh_client__get_immediate()`
   - Fetches single object via GET request
   - More expensive, used when batch isn't possible

### Shared Cache

GVFS uses a shared object cache (`gvfs.sharedCache` config) to avoid
redundant downloads across repos. Key points:

- Objects are written to `gh_client__chosen_odb`, typically the shared cache
- The shared cache is an ODB alternate, not the primary `.git/objects`
- After writing objects, the correct packfile store must be refreshed

### Object Database Structure

The ODB has multiple sources in a linked list:
```
the_repository->objects->sources  ->  sources->next  ->  ...
         (primary .git/objects)        (alternates)
```

Each source has its own:
- `packfiles` - Packfile store
- `loose` - Loose object cache
- `path` - Directory path

## GVFS Integration Points

This section describes how GVFS-specific code hooks into Git's core object
machinery. For a general overview of Git's source code, see the "A birds-eye
view of Git's source code" section in `Documentation/user-manual.adoc`.

### Key Files

| File                    | Purpose                                          |
|-------------------------|--------------------------------------------------|
| `gvfs-helper.c`         | Standalone helper for Azure Repos via GVFS       |
| `gvfs-helper-client.c`  | Client that communicates with gvfs-helper        |
| `gvfs.c`, `gvfs.h`      | GVFS configuration and utility functions         |
| `odb.c`                 | Object database - GVFS hooks for on-demand fetch |
| `promisor-remote.c`     | Promisor remote - GVFS helper for batch fetches  |
| `environment.h`         | Declares `core_use_gvfs_helper` and related      |

### Object Lookup Flow

When Git needs an object, it calls `do_oid_object_info_extended()` in `odb.c`.
The GVFS integration adds two fetch paths to this function:

1. **Immediate fetch** (lines ~935-957 in odb.c):
   ```c
   if (core_use_gvfs_helper && !tried_gvfs_helper) {
       gh_client__get_immediate(real, &ghc);
       tried_gvfs_helper = 1;
       if (ghc != GHC__CREATED__NOTHING)
           continue;  /* retry lookup */
   }
   ```

2. **Promisor/batch fetch** (via `promisor_remote_get_direct()` in
   promisor-remote.c):
   ```c
   if (core_use_gvfs_helper) {
       gh_client__queue_oid_array(oids, oid_nr);
       gh_client__drain_queue(&ghc);
       return;
   }
   ```

The batch path is more efficient as it fetches multiple objects in one request.

### Shared Cache Integration

The shared cache is configured via `gvfs.sharedCache` and handled in `odb.c`:

1. `odb_add_source()` (lines ~97-153) detects when an alternate matches the
   configured shared cache path
2. `odb_prepare_alternates()` (lines ~674-707) adds the shared cache as an
   alternate if not already present
3. `gh_client__choose_odb()` in `gvfs-helper-client.c` selects the shared cache
   as the target for downloaded objects

### gvfs-helper Communication

The client (`gvfs-helper-client.c`) communicates with `gvfs-helper` using
Git's long-running process protocol (see
`Documentation/technical/long-running-process-protocol.adoc`):

```
git process                    gvfs-helper
    |                              |
    |-- objects.post ------------->|
    |-- <oid1> ------------------->|
    |-- <oid2> ------------------->|
    |-- <flush> ------------------>|
    |                              |  (fetches from server)
    |<-- odb <path> ---------------|
    |<-- packfile <name> ----------|
    |<-- ok -----------------------|
    |<-- <flush> ------------------|
```

After receiving a packfile response, the client must call
`packfile_store_reprepare()` on the correct ODB source so that
subsequent object lookups can find the newly downloaded objects.

## Debugging Techniques

### Debugging Philosophy

Debugging is not about guessing fixes and seeing if they work. It is about
building a complete understanding of the problem before attempting any fix.
The goal is not speed to a "fix" but confidence that you understand and have
addressed the root cause.

**Respect turnaround time.** If seeing the result of an attempted fix takes
7-10 minutes (e.g., a CI workflow run), you cannot afford to guess. Each
iteration costs human time and attention. Before pushing any change:

1. Ask: "What information am I missing to competently assess this situation?"
2. Add diagnostic output that will provide that information if the fix fails.
3. Consider whether you can reproduce the issue locally where turnaround is
   seconds, not minutes.

**Understand before acting.** Before attempting any fix:

1. When investigating a regression between two versions, start by examining
   the code diff. Analyze what actually changed before running any tests.
   Tests confirm hypotheses; reading the diff gives you the hypothesis.
2. Trace the code flow completely. Read the relevant Makefiles, scripts, and
   source files. Understand what each component does and how they interact.
3. Identify all changes that could have contributed: upstream commits,
   downstream patches, infrastructure changes (CI runner updates, dependency
   upgrades).
4. For each potential cause, find the specific commit, its date, its intent,
   and how it interacts with other components.
5. Build a hypothesis. Then ask: "How would I confirm or disprove this?"

**Do not assume root cause from symptoms.** A symptom appearing on one
platform does not mean the bug is platform-specific. The cause may be in
shared code that manifests differently across platforms. Similarly, a passing
test on one platform when it fails on another is data to investigate, not
grounds to conclude "works for me."

**When a fix does not work, investigate why.** If you expected a fix to work
and it did not, that is valuable information. Do not abandon that line of
thinking and try something else. Instead:

1. Ask: "Why didn't that work? What does this tell me about my understanding?"
2. Add more targeted diagnostics to understand the discrepancy.
3. Re-examine your assumptions. Something you believed to be true is false.

**Add diagnostics proactively.** Before pushing a fix attempt, add diagnostic
output that will:

1. Confirm the state you expect to see if the fix works.
2. Reveal the actual state if it does not.
3. Provide enough context to understand the next step without another round
   trip.

For build failures, this might include: library paths, compiler flags,
architecture information, symbol tables, file existence checks, environment
variables.

**Build confidence before pushing.** A fix should not be a guess. You should
be able to explain:

1. What was the root cause?
2. Why does this fix address it?
3. What other ways could this problem be solved?
4. Am I choosing the "most correct" or "most effective" approach?
5. What evidence confirms your understanding?
6. What could still go wrong, and how would you detect it?

### Searching the Codebase

In particular when debugging failures that printed error messages, it is often
a useful thing to search for those error messages; If parts of the message seem
mutable (e.g. commit OIDs), those will not be hard-coded and the search needs
to accommodate for that by using regular expressions or prefix matches.

Use `git grep` for fast code searches:

```bash
git grep -n -i "pattern"            # Case-insensitive search with line numbers
git grep -n -w "word"                 # Whole-word matches only
git grep -n -i "pattern" -- "*.c"     # Search only C files
```

### Trace2 for Object Fetching

Enable tracing to see object fetch patterns:
```bash
GIT_TRACE2_EVENT=/path/to/trace.txt git <command>
```

Key trace messages:
- `gh_client__queue_oid: <oid>` - Object added to batch queue
- `gh_client__get_immediate: <oid>` - Object fetched immediately
- `gh-client/objects/post` - Batch POST request region

### Instrumenting Git Internals During Tests

When adding debug output to Git's C code during test investigation,
`fprintf(stderr, ...)` from git subprocesses spawned by the test framework
is typically swallowed (redirected or discarded by the test harness). Use
Trace2 instead:

```c
trace2_data_intmax("index", NULL, "my_debug/cache_nr", istate->cache_nr);
trace2_data_string("index", NULL, "my_debug/state", some_string);
```

Then run the test with `GIT_TRACE2_EVENT` or `GIT_TRACE2_PERF` pointing to
a file, and grep the output. This integrates with Git's existing tracing
infrastructure and survives the test framework's output management.

As a last resort (e.g. when Trace2 is not initialized yet at the point you
need to instrument), write to a fixed file path:

```c
FILE *f = fopen("/tmp/debug.log", "a");
if (f) { fprintf(f, "state: %u\n", value); fclose(f); }
```

### Comparing Branches After Rebase

```bash
# See what patches exist in a new branch but not old
git log --oneline old-branch..new-branch
# or
git range-diff -s --right-only old-branch...new-branch

# Compare specific files between branches
git diff old-branch..new-branch -- path/to/file.c
# or
git log -p old-branch..new-branch -- path/to/file.c
# or even
git log -L start-line,end-line:path/to/file.c old-branch..new-branch --

# Find upstream changes between tags
git log --oneline --first-parent v2.52.0..v2.53.0
```

### Test Failure Investigation

1. **Reproduce with tracing**: Run test with `-ivx` flags
2. **Check timestamps**: Look at `t_abs` in trace to understand ordering
3. **Compare with working version**: Build and test the previous version
4. **Bisect if needed**: Use `git bisect` to find the breaking commit

Bisecting failures introduced by upstream commits require some stunts to
apply the downstream changes for every bisection step. This can be done by
squashing all downstream changes into one throw-away commit and then
cherry-picking that (typically, there will be merge conflicts the farther
away from the original branch point the commit is cherry-picked to, so it
often makes sense to squash both old and new downstream changes, and then
to "interpolate" between them when encountering merge conflicts).

### Bisecting Failures in `seen`

When a topic passes on its own but fails after being merged to `seen`, the
failure is caused by interaction with another in-flight topic. To identify
the culprit:

1. Fetch the exact `seen` commit from the failing CI run (get the SHA from
   the workflow run metadata via the GitHub API).
2. Use a worktree checked out at that `seen` commit.
3. Bisect the first-parent history between `upstream/master` and `seen~1`
   (excluding the topic's own merge). At each bisection step, merge the
   topic in temporarily, build, run the test, then undo the merge.
4. Write a `git bisect run` script that automates this. Key pitfalls:
   - The script must `unset` test environment variables (especially
     `GIT_TEST_SPLIT_INDEX`) before cleanup operations like
     `git checkout -f`, otherwise the worktree's own index can get
     corrupted.
   - Use `git checkout -f "$ORIG"` (not `git reset --hard`) to undo the
     temporary merge, since `reset --hard` under split-index can corrupt.
   - Save the current commit OID at the start (`ORIG=$(git rev-parse HEAD)`)
     because `ORIG_HEAD` is unreliable during bisect.
   - On merge conflict, return 125 (skip) and `git merge --abort`.
5. Store the alias for running with the full set of CI test variables as a
   repository-local alias (to avoid repeating the long export list and to
   allow the user to approve the tool call once).

### CI/Workflow Failure Investigation

When a CI workflow fails, the debugging process has a high cost per iteration.
Approach these failures methodically:

**1. Establish what changed.** Before looking at the error, identify:

- What was the last successful run? What version/commit was it based on?
- What changed between then and now? (upstream commits, downstream patches,
  runner image updates, dependency changes)
- Use the GitHub API to retrieve run metadata and compare.

**2. Analyze the error deeply.** Read the full error message and surrounding
context. Understand:

- What command failed?
- What were its inputs (flags, environment, paths)?
- What did it expect vs. what did it get?

**3. Trace the code flow locally.** Before making any CI changes:

- Read the workflow YAML, Makefiles, and scripts involved.
- Understand how variables flow from one to another.
- Identify where the failing values come from.

**4. Reproduce locally if possible.** Many CI failures can be reproduced
locally with faster turnaround:

- For build failures: replicate the build environment and commands.
- For macOS issues: if you lack a Mac, at least trace the Makefile logic
  to understand what flags should be set and why.
- For test failures that only appear in specific CI jobs (like
  `linux-TEST-vars`): reproduce with the _exact_ set of environment
  variables that job sets. Check `ci/run-build-and-tests.sh` for the
  job's variable block. Do not assume a single variable (e.g.
  `GIT_TEST_SPLIT_INDEX`) is sufficient; other variables may contribute
  to the failure path.
- When a test fails in `seen` but not on the topic branch alone, check
  out the exact `seen` commit from the failing CI run (get the SHA from
  the workflow run metadata) and reproduce against that. The interaction
  with other in-flight topics is the likely cause.

**5. Do not assume CI coverage from platform support.** When asking "why
does platform X not see this bug?", verify whether CI actually tests that
combination on that platform. For example, `GIT_TEST_SPLIT_INDEX=yes` is
only set by `linux-TEST-vars`; there is no equivalent `osx-TEST-vars` or
`windows-TEST-vars` job. A bug that only manifests under split-index
testing may be present on all platforms but only caught on Linux.

**5. Add comprehensive diagnostics on first attempt.** If you must push to
CI to test, make that push count:

- Add diagnostic output for every hypothesis you have.
- Print the values of key variables, paths, flags.
- Show the state before and after key operations.
- Design diagnostics to distinguish between your hypotheses.

**6. Do not remove diagnostics until the problem is solved.** Keep them in
"drop!" commits so they can be easily removed later but provide information
if subsequent fixes also fail.

**7. When a fix fails, treat it as data.** The failure tells you something.
Your mental model was wrong. Figure out what before trying again.

## Git Workflow

This repository is a shared development environment, not a sandbox. Exercise
caution with all Git operations.

### Committing Changes

Never use `git add -A` or `git add .` - these commands will stage untracked
build artifacts, editor swap files, and other detritus that should not be
committed. Always specify pathspecs explicitly:

```bash
# Good: stage and commit specific files
git commit -sm "your message here" path/to/file.c other/file.h

# Bad: stages everything, including untracked garbage
git add -A && git commit -m "message"
```

The `-s` flag adds a Signed-off-by trailer, which is required for this
project.

When AI assistance is used to author or co-author a commit, add a
Co-authored-by trailer identifying the model:

```bash
git commit -s --trailer "Co-authored-by: <model-name>" -m "message" file.c
```

### Pushing Changes

Never push without explicit user permission. The user controls when and
where changes are pushed. This is especially critical because:

- The repository has multiple remotes with different purposes
- Force-pushing to the wrong remote can cause significant damage
- Tags require special handling (`git push --tags` or explicit tag pushes)

Wait for the user to push, or ask explicitly before pushing.

### Making Code Changes

**Minimal, surgical changes.** Make the smallest possible change to achieve
the goal. Do not rewrite entire files or functions when a targeted edit
suffices. When removing functionality:

1. Remove the code paths that invoke the unwanted functionality
2. Compile to identify what is now unused
3. Remove the unused functions one at a time
4. Repeat until clean

**No fly-by changes.** Do not make changes that were not requested, even if
they seem like improvements (renaming variables, reformatting untouched code,
"fixing" things not part of the task). If you believe a change would be
beneficial but it was not requested, ask for permission first.

**The human is the driver.** Execute what is asked. If you think something
should be done differently, ask---do not just do it.

### Commit Message Quality

Good commit messages use flowing English prose, not bullet points. They
clearly state:

- **Context**: What situation prompted this change? Include URLs to failing
  CI runs, issue numbers, or other references that future readers will need.
- **Intent**: What is this change trying to accomplish?
- **Justification**: Why is this the right approach? What alternatives were
  considered? When choosing between approaches based on performance,
  include measured timings so future readers understand the tradeoffs.
- **Implementation**: How does the change work? (Only for non-obvious parts;
  don't describe what's clear from the diff.)

Include exact error messages rather than vague descriptions. If a build
failed with `Undefined symbols for architecture arm64: "_iconv"`, put that
in the commit message - don't just say "fixed a linker error."

Wrap commit messages at 76 columns per line.

### Commit Prefixes for Rebase Workflows

This repository uses interactive rebase with autosquash. Commit prefixes
signal intent:

- **`fixup! <original title>`**: Will be squashed into the referenced commit
  during rebase. The title after `fixup!` must match the original commit's
  title exactly.
- **`drop!`**: Indicates a commit that should be dropped before the final
  merge. Used for debugging, temporary workarounds, or experiments.

To find the correct title for a fixup commit:

```bash
git log --oneline path/to/changed/file | head -10
```

Then use the exact title:

```bash
git commit -sm "fixup! release: add Mac OSX installer build" path/to/file
```

## Rebasing Workflow

Rebases are the bread and butter of Microsoft Git: Whenever a new Git for
Windows version is released, the previous `vfs-<version>` branch is rebased
wholesale to that new upstream version. Once that is done, the upstream
version is pushed as `vfs-<new-version>` and the rebased branch as
`tentative/vfs-<new-version>` and a PR is opened to merge the latter into
the former.

### High-Risk Areas

When rebasing onto new upstream versions, pay special attention to:

| Area              | Files                      | Why                      |
|-------------------|----------------------------|--------------------------|
| Object lookup     | `odb.c`, `object-file.c`   | GVFS hooks lookup paths  |
| Packfile handling | `packfile.c`, `packfile.h` | Shared cache packfiles   |
| Repository struct | `repository.[ch]`,         | GVFS adds custom fields  |
| Config parsing    | `config.c`                 | GVFS-specific options    |

### When to Skip a Patch

Use `git rebase --skip` when the patch is already in the new base:

- **Upstreamed**: The patch was accepted upstream and is now in `seen`
- **Backported**: A fix we backported is now included in the upstream base
- **Superseded**: HEAD already contains evolved code that includes this
  change

Signs to skip rather than resolve: HEAD has the functionality, the
conflict would discard the patch entirely, or `git range-diff` shows
the downstream and upstream patches are equivalent.

To find the corresponding upstream commit for a conflicting patch:

```bash
git range-diff --left-only REBASE_HEAD^! REBASE_HEAD..
```

### Resolving Merge Conflicts

When resolving merge conflicts during a rebase (especially when squashing
fixups), the goal is to **apply the minimal surgical change** that the
patch intended, not to reconstruct entire functions or add duplicate code.

#### 1. Understand What the Patch Wants

First, examine the patch being applied:

```bash
git show REBASE_HEAD
```

Look at the actual changes (lines starting with `-` and `+`):
- What lines are being removed?
- What lines are being added?
- What is the context (function name, nearby code)?

**Key insight**: The patch shows the *intent*---a specific small change to
make. Focus on this, not on the conflict markers' content.

**Code movement detection**: If the patch shows large changes, check with
`--ignore-space-change`:

```bash
git show <conflicted-commit> --ignore-space-change
```

This reveals whether the commit is primarily **moving code** (lots of
whitespace changes) or making **logic changes** (actual code modifications).
When code was moved and re-indented, focus only on the non-whitespace
changes when resolving the conflict.

#### 2. Understand Where the Code Is Now

The conflict occurred because the code moved or changed since the patch was
created. Find where that code actually exists now:

```bash
# If the patch was changing a specific pattern, find all occurrences
git grep -n "pattern from patch"

# View the conflicted file around those locations
```

**Common mistake**: Assuming the conflict markers show you what to do. They
do not---they just show where Git got confused.

#### 3. Apply the Surgical Change

Make **only** the change the patch intended, but in the current location:

- If the patch adds `--abbrev=12` to a range-diff call, find where that
  range-diff call is NOW and add it there
- If the patch changes a `.split()` pattern, find where that pattern is NOW
  and change it
- Do not copy entire functions from the conflict markers
- Do not create duplicates

#### 4. Remove ALL Conflict Markers

Conflict markers make the file invalid code:
```
<<<<<<< HEAD
=======
>>>>>>> commit-hash
```

**All three types of markers must be completely removed.**

#### 5. Verify the Resolution

**Critical**: After staging your resolution, verify it matches the patch
intent:

```bash
# Compare your staged changes to the original patch
git diff --cached
git rebase --show-current-patch

# Or more directly, compare to REBASE_HEAD
git diff --cached
git show REBASE_HEAD

# For code that was moved/re-indented, ignore whitespace
git diff --cached --ignore-space-change
git show REBASE_HEAD --ignore-space-change
```

**Verify, verify, verify**: The output of `git diff --cached` should
correspond closely to the diff in `git show REBASE_HEAD`. The line numbers
and context will differ (because code moved), but the actual changes (the
`-` and `+` lines) should match the patch intent.

**After completing a rebase**, always verify the final result:

```bash
# Compare tree before and after rebase
git diff @{1}

# Shows what changed in each rebased commit
git range-diff @{1}...
```

If the rebase was onto the same base commit (e.g., squashing fixups), the
`git diff @{1}` should be empty---this proves the rebase only reorganized
commits without changing the end result. If the rebase was onto a new base
commit (e.g., rebasing onto a new upstream release), the diff should match
the difference between the old and new base commits, modulo any changes
from upstreamed or backported patches. The `git range-diff @{1}...` shows
the intended amendments (like adding `--abbrev=12`) were correctly applied
to each commit.

### Conflict Resolution Red Flags

These indicate you are doing it wrong:

- Your diff adds hundreds of lines when the patch only changed 3
- Conflict markers remain in the file
- Functions appear twice in the file
- You added `<<<<<<< HEAD` or `=======` to the staged changes
- Syntax check fails after resolution

### Key Conflict Resolution Lessons

1. **Context changes, intent does not** - The patch's line numbers are
   wrong, but the change is right
2. **Conflict markers lie** - They show you where Git got confused, not
   what you should do
3. **One change at a time** - If the patch adds one line, your resolution
   should add one line
4. **Verify, verify, verify** - `git diff --cached` should match
   `git show REBASE_HEAD` (modulo context)
5. **Post-rebase verification** - `git diff @{1}` (empty) and
   `git range-diff @{1}...` (shows amendments)
6. **Ignore whitespace for code moves** - Use `--ignore-space-change` to
   see the actual logic changes when code was moved and re-indented
7. **When in doubt, look at the range-diff** - `git range-diff` shows if
   you matched the intent

### Useful Rebase Tools

- `git rebase --show-current-patch` - See what change is being applied
- `git show REBASE_HEAD` - Alternative to above, works better with
  `--ignore-space-change`
- `git show <commit> --ignore-space-change` - See only logic changes, not
  whitespace/indentation
- `git grep -n "pattern"` - Find where code moved to
- `git log -L <start>,<end>:<file> REBASE_HEAD..HEAD` - See how upstream
  modified a line range since the original patch; invaluable for
  understanding how conflicting lines changed
- `git diff --cached` - After staging resolution, verify it matches
  REBASE_HEAD
- `git diff @{1}` - After rebase, compare tree before/after
- `git range-diff @{1}...` - After rebase, verify intended changes were made
- `git range-diff A^! B^!` - Compare original patch to your resolution

### Leveraging Rerere

Git's "reuse recorded resolution" (`rerere`) feature automatically records
how you resolve conflicts and replays those resolutions when the same
conflict recurs. This is invaluable for repeated rebases where the same
downstream patches conflict with similar upstream changes.

When you see `Staged 'file' using previous resolution`, Git has applied a
previously recorded resolution. Always verify these auto-resolutions are
still correct---upstream context may have changed enough that the old
resolution no longer applies cleanly.

To enable rerere:
```bash
git config --global rerere.enabled true
```

### Automation Tips

When running rebases in automated or scripted contexts, disable the pager
to avoid hangs:

```bash
GIT_PAGER=cat git range-diff ...
# or
git --no-pager log ...
```

### Non-interactive "Interactive" Rebases

AI agents cannot drive interactive editors reliably. Instead, insert a
`break` as the first todo command so the rebase stops immediately, then
edit the todo file directly:

```bash
# Start the rebase, stopping before any picks execute
GIT_SEQUENCE_EDITOR='sed -i 1ib' git rebase -ir <base>

# Find and edit the todo file with the view/edit tools
git rev-parse --git-path rebase-merge/git-rebase-todo

# After editing the todo, continue (GIT_EDITOR=true suppresses the
# editor that fixup -C and amend! commands would otherwise open)
GIT_EDITOR=true git rebase --continue
```

### Scripted Hunk Staging

`git add -p` is interactive by default, but its prompts follow a
predictable protocol. To stage the first hunk of a file without
human interaction:

```bash
printf '%s\n' s y q | git add -p <file>
```

The `s` splits a large hunk, `y` stages the first sub-hunk, and `q`
quits. Adjust the sequence for different hunk selections (e.g.,
`y y n q` to stage the first two hunks but skip the third).

### Finding Which Commit to Amend

When a working-tree change belongs in an earlier commit (an `hg absorb`
workflow), use `git log -L` to find which commit last touched the
relevant lines:

```bash
git log -L <start>,+<count>:<file>
```

This shows the full history of a line range, making it easy to identify
the commit whose title you need for a `fixup!` commit. This is far more
surgical than grepping through full diffs.

### Fixup Commits

Downstream patches sometimes require adjustment due to changes in the
environment they operate in. These changes may come from:

- **Upstream code changes**: API modifications, struct field moves,
  declarations relocating between headers, or semantic changes in functions
  that downstream code depends on.
- **External environment changes**: CI runner image updates, toolchain
  upgrades, dependency version changes, or platform behavior shifts.

In both cases, create a `fixup!` commit that will be squashed into the
original downstream patch during the next interactive rebase. The commit
message body must precisely document the change that necessitated the fix:

- For upstream changes: reference the specific upstream commit (by OID or
  title) and explain what it changed.
- For external changes: include URLs to failing CI runs, document what
  changed in the environment (e.g., "GitHub Actions macos-latest runner
  upgraded from macOS 14 to macOS 15"), and note the exact error message.

This documentation is essential because the fixup will be squashed away,
and the context will be lost if not recorded in the commit message that
gets squashed into.

Run affected tests before finalizing.

### GitHub Actions Version Bumps (Dependabot)

The repository uses Dependabot to monitor GitHub Actions versions
(configured in `.github/dependabot.yml`). When Dependabot proposes
version bumps, the resulting changes must be split by ownership layer,
because each layer is handled differently during rebases.

There are three ownership layers for workflows in this repository:

1. **Upstream Git**: Core CI workflows and jobs that exist in the upstream
   Git project (e.g., the core jobs in `.github/workflows/main.yml`,
   `.github/workflows/check-whitespace.yml`).
2. **Git for Windows**: Additional workflows and workflow sections added
   by Git for Windows on top of upstream (e.g., GfW-specific jobs in
   `main.yml`, `.github/workflows/check-style.yml`,
   `.github/workflows/l10n.yml`).
3. **Microsoft Git**: Fork-specific workflows added by the Microsoft Git
   fork (e.g., `.github/workflows/build-git-installers.yml`,
   `.github/workflows/release-*.yml`,
   `.github/workflows/scalar-functional-tests.yml`,
   `.github/workflows/vfs-functional-tests.yml`).

Ownership is determined **per changed line/section**, not per file.
A single workflow file like `main.yml` contains sections owned by all
three layers. Use `git blame` or `git log -L` on the changed lines to
determine which downstream commit introduced them.

**How to handle each layer:**

- **Upstream Git**: Create standalone commits with rewritten commit
  messages (not the auto-generated Dependabot text). The message must
  include a risk analysis: what the new version changes, whether it
  affects our usage, and any preconditions (e.g., minimum runner
  version). These commits are intended to be submitted upstream via
  GitGitGadget.
- **Git for Windows**: Create `fixup!` commits targeting the Git for
  Windows commit that introduced the affected workflow or section. Use
  `git log -L` or `git blame` to find the right target.
- **Microsoft Git**: Create `fixup!` commits targeting the Microsoft
  Git commit that introduced the affected workflow or section.

When a single Dependabot update touches lines from multiple layers,
**split the changes into separate commits**, one per layer. Each commit
follows the rules for its respective layer.

### Common Adaptation Patterns

**Struct field moves**: When upstream moves fields between structs, update
all GVFS code that accesses those fields.

**API changes**: When upstream changes function signatures, update callers
in GVFS code and verify semantics are preserved.

**New abstractions**: When upstream introduces new layers (e.g., per-source
packfile stores), ensure GVFS code uses the correct instance (e.g., the
shared cache source, not just the first source).

## Coding Conventions

The Git project maintains a charmingly old-school, Unix-greybeard aesthetic
when it comes to text encoding. In the spirit of the PDP-11 and Bell Labs
terminal sessions of yore:

- **ASCII only**: Avoid Unicode characters in source code, comments, and
  documentation. Use `->` instead of `→`, `--` instead of `—`, and so on.
  To verify your changes contain no non-ASCII characters:
  ```
  git diff | LC_ALL=C grep '[^ -~]'
  ```
- **80 columns per line**: The mailing list veterans will "kindly" remind you
  that lines should not exceed 80 characters (they do mean columns, but
  let's not split beards or hairs about wide glyphs).
  First, check for whitespace errors (trailing whitespace, mid-line tabs, etc.):
  ```
  git diff --check
  ```
  Once that passes, you know tabs only appear at line beginnings, so each
  tab equals exactly 8 columns. To find lines exceeding 80 columns:
  ```
  git diff --no-color | grep '^+' | sed 's/\t/        /g' | grep '.\{82\}'
  ```
  (We use 82 because diff output prefixes added lines with `+`.)
- **Tabs for indentation**: The codebase uses tabs, not spaces.
- **No trailing whitespace**: Clean up your lines.

**Pre-commit checklist.** Run all three checks before every commit:

```bash
git diff --check &&
git diff --no-color | LC_ALL=C grep '[^ -~]' &&
  echo "ERROR: non-ASCII characters found" &&
git diff --no-color | grep '^+' | sed 's/\t/        /g' |
  grep '.\{82\}' &&
  echo "ERROR: lines exceed 80 columns"
```

The first command catches whitespace errors. If either of the latter
two produces output, fix the offending lines before committing. Note
that these checks apply to commit messages as well (wrap at 76 columns
for messages, 80 for code).

See `Documentation/CodingGuidelines` for the full set of conventions.

### strbuf patterns

Use `strbuf_addf()` with string continuation for multi-line content instead
of multiple `strbuf_addstr()` calls:

```c
/* Good */
strbuf_addf(&buf,
            "tree %s\n"
            "author %s\n"
            "committer %s\n"
            "\ncommit message\n",
            tree_hex, author, committer);

/* Avoid */
strbuf_addstr(&buf, "tree ");
strbuf_addstr(&buf, tree_hex);
strbuf_addstr(&buf, "\nauthor ");
/* ... */
```

Choose descriptive variable names (`header` for pack headers, not generic
`buf`; use `buf` for the secondary strbuf if you cannot reuse the first).

## Platform Considerations

### Windows-specific issues

On Windows, `unsigned long` is 32 bits even on 64-bit systems. Use `size_t`
for sizes that may exceed 4GB. Be careful with format strings: use `PRIuMAX`
with a cast for `size_t` values.

## Configuration Options

### GVFS-specific

| Config                 | Purpose                                    |
|------------------------|--------------------------------------------|
| `core.useGVFSHelper`   | Enable GVFS helper for object fetching     |
| `gvfs.sharedCache`     | Path to shared object cache directory      |
| `gvfs.cache-server`    | URL of GVFS cache server                   |
| `gvfs.fallback`        | Whether to fall back to origin if CS fails |
| `gvfs.sessionKey`      | Custom session key for GVFS HTTP headers   |
| `gvfs.prefetchThreads` | Parallel index-pack processes for prefetch |

### Rename detection and blame

These configuration options are downstream enhancements that do not
exist in upstream Git (yet).

| Config                   | Purpose                                  |
|--------------------------|------------------------------------------|
| `diff.renameThreshold`   | Min similarity for rename detection      |
| `merge.renameThreshold`  | Override for merges                      |
| `status.renameThreshold` | Override for status                      |
| `blame.renames`          | Enable/disable rename following in blame |
| `blame.renameThreshold`  | Min similarity for blame renames         |
| `blame.renameLimit`      | Limit on blame rename detection candidates |

## Contributing to Upstream Git via GitGitGadget

### Overview

The upstream Git project accepts contributions via the mailing list
(`git@vger.kernel.org`). [GitGitGadget](https://gitgitgadget.github.io/)
bridges GitHub PRs to the mailing list: you push a branch to your GitHub
fork, open a PR against https://github.com/gitgitgadget/git, and
GitGitGadget formats and sends the patches.

### Workflow

1. Push the topic branch to your personal fork on GitHub (the remote
   that points at `https://github.com/<you>/git`).
2. Open a PR from `<you>:<branch>` against `gitgitgadget/git`'s `master`.
3. The PR title becomes the patch series subject; the PR body becomes the
   cover letter. Use
   `gh pr create --repo gitgitgadget/git --head <you>:<branch>`.
4. Use `/submit` as a PR comment to send patches to the mailing list.
5. After review feedback, update the branch, force-push, and `/submit` again.

### Branch Naming

Do **not** use an initials prefix (like `ds/` or `js/`). That convention is
used by the Git maintainer when picking up topics, not by contributors. Use
descriptive names like `tests-explicit-bare-repo`.

### Cover Letter Style

The PR body is the cover letter. It should be plain text (not Markdown with
headers or bullet formatting), since it will be sent as email. Structure:

- A brief subject line (the PR title, e.g. "tests: access bare repositories
  explicitly")
- Motivation: why is this change needed?
- Summary: what does the series do? What patterns/techniques does it use?
- Scope: is this part of a larger effort? If so, link to the tracking PR.

Keep it factual and measured. Avoid framing changes in terms of security
when contributing to upstream Git; frame them as robustness, correctness,
or preparation for future defaults.

### Commit Message Conventions (Upstream Git)

Upstream Git commit messages follow stricter conventions than the Microsoft
Git fork:

- **Subject line**: `<area>: <description>` (lowercase after the colon).
  The `<area>` is typically a file name without extension (e.g. `t0001`,
  `setup`, `scalar`) or a subsystem name (e.g. `tests`, `refs`).
- **Body**: Flowing English prose, no bullet points. Wrap at 76 columns.
- **ASCII only**: No Unicode characters anywhere in the message.
- **Trailers**: `Signed-off-by` is mandatory. `Assisted-by` for AI.
- The subject line must accurately describe the diff content. If a commit
  adds `--git-dir=.` to one invocation, do not title it "wrap bare repo
  commands in subshell with `GIT_DIR`".

### Patch Series with Dependencies

When contributing a branch thicket (multiple related patch series with
dependencies), submit the foundation series first and note the overall
effort in the cover letter with a link to the tracking PR or `compare`
URL. Submit dependent series after earlier ones land in `seen`.

Use `git replay --onto <target> <base>..<branch>` to test whether a
sub-branch applies cleanly to a given base (e.g., `upstream/master` or
`upstream/seen`) without touching the working tree. By default (since
the `--ref-action` default changed to `update`), `git replay` updates
named refs in the range directly, producing no stdout output. Use
`--ref-action=print` to get the old behavior of printing `update-ref`
commands to stdout instead. Always verify that `git replay` actually
did something by checking the reflog of the affected branches.

## Working with Worktrees

### General Principles

Use worktrees to work on multiple topics simultaneously without stashing
or switching branches. Keep worktrees as subdirectories of the main
repository and add them to `.git/info/exclude` so they do not show up
as untracked files.

```bash
git worktree add <name> <branch>
echo "<name>" >> .git/info/exclude
```

### Rewriting Commits with `--update-refs`

When rewriting history in a worktree (e.g., fixing a commit message via
`amend!` + autosquash), use `--update-refs` so that other local branches
pointing into the rewritten range are updated automatically:

```bash
# Create a local branch at the commit to be pushed
git branch <push-name> <tip>

# Create the amend! commit and autosquash
git commit --allow-empty -F <message-file>
GIT_SEQUENCE_EDITOR=true GIT_EDITOR=true \
  git rebase -i --autosquash --update-refs <base>

# Verify: tree should be identical
git diff <push-name>@{1}..<push-name>

# Force-push the updated branch
git push <remote> <push-name> --force-with-lease
```

The `--update-refs` flag is essential: without it, only the checked-out
branch is rewritten and other branches become stale, pointing at
pre-rewrite commits.

### Verifying Rebase Results

After any rebase, verify that the tree content is unchanged (unless you
intentionally modified it):

```bash
git diff @{1}              # Should be empty for pure rewording
git range-diff @{1}...     # Shows per-commit changes
```

## Analyzing Branch Thickets

When a branch is structured as a sequence of merged sub-branches (a
"branch thicket"), use the merge structure to extract sub-branches:

```bash
# List the merge commits (sub-branches)
git log --oneline --first-parent <branch>...upstream/master | grep 'Merge branch'

# Extract commits for a specific sub-branch (second parent of its merge)
git log --oneline <merge>^1..<merge>^2

# Find what each sub-branch forks from
git log -1 --format='%H %s' <first-commit-in-sub-branch>^
```

Use `git replay` to test whether sub-branches can be rebased onto a new
base without conflicts. This replaces speculation about "overlapping files"
with actual evidence:

```bash
git replay --onto upstream/master <old-base>..<branch>
```

If the range contains merge commits, `git replay` will fail with "replaying
merge commits is not supported yet!" In that case, identify the linear
commit range and replay just those commits.

## Resources

- [GVFS Protocol Specification](https://github.com/microsoft/VFSForGit)
- [Scalar Documentation](https://github.com/microsoft/scalar)
- [Git Internals](https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain)
- [GitGitGadget](https://gitgitgadget.github.io/) - Bridge GitHub PRs to
  the Git mailing list
- [Git Mailing List Archive](https://lore.kernel.org/git/) - Searchable
  archive of all upstream discussion
