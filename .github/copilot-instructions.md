## General

- Be extremely consise and sacrifice grammar for the sake of concision.
- Summarize shortly at the end.
- Never generate summary file.
- Autosave with trigger linting by ruff.
- Always run with the venv python: `.venv/bin/python` at the root folder of this project
- use `gtimeout` instead of `timeout`

## Code Search Preferences

Prefer these tools over `grep`, `find`, `sed`, `awk`:

- **`ast-grep` (`sg`)** - Syntax-aware search/rewrite for TypeScript code
- **`osgrep`** - Semantic search when you don't know exact strings/patterns

## Plans

- At the end of each plan, give me a list of unresolved questions to answer, if any. Make the questions extremely concise. Sacrifice grammar for the sake of concision.

## AST-Grep for TypeScript

`ast-grep` (command: `sg`) is a structural code search/rewrite tool. Prefer over `grep` for syntax-aware searches.

### Pattern Syntax

- `$VAR` - matches single AST node (like regex `.`)
- `$$$ARGS` - matches zero or more nodes
- Valid names: `$META`, `$META_VAR`, `$_` (uppercase + underscore only)
- Same metavariable name = must match same content (`$A == $A` matches `x == x`, not `x == y`)

### Common TypeScript Commands

```bash
# Search patterns (always use -l typescript for .ts files)
sg -p 'console.log($MSG)' -l typescript src/
sg -p 'import { $$$IMPORTS } from "$MOD"' -l typescript
sg -p 'async function $NAME($$$PARAMS) { $$$BODY }' -l typescript
sg -p 'await $PROMISE' -l typescript

# Rewrite with -r
sg -p 'console.log($MSG)' -r 'logger.info($MSG)' -l typescript src/
sg -p 'fs.rmdir($PATH)' -r 'fs.rm($PATH, { recursive: true })' -l typescript

# List files only
sg -p 'useEffect($$$)' -l typescript --heading never

# Interactive edit
sg -p 'deprecated($$$)' -r 'newApi($$$)' -i -l typescript
```

### Useful Flags

| Flag                | Description                       |
| ------------------- | --------------------------------- |
| `-l, --lang`        | Language (`typescript`, `tsx`)    |
| `-r, --rewrite`     | Replacement pattern               |
| `-i, --interactive` | Confirm each change               |
| `-U, --update-all`  | Apply all without confirm         |
| `--json`            | JSON output                       |
| `-A/-B/-C`          | Context lines after/before/around |

### Tips

- Always quote patterns: `'pattern'` to avoid shell expansion
- Patterns must be valid parseable code
- `$_VAR` (underscore prefix) = non-capturing, won't enforce same content

## osgrep Semantic Search

`osgrep` is a local semantic code search tool. Use it to find concepts, not just strings.

### When to Use

- Finding where concepts are implemented ("where do transactions get created?")
- Searching for patterns across codebase when you don't know exact string/file
- Prefer over `grep` when searching for meaning, not literal text

### Commands

- `osgrep "<query>"` - Semantic search (default)
- `osgrep index` - Pre-warm cache or refresh after big changes
- `osgrep index --dry-run` - See what would be indexed

### Useful Flags

| Flag             | Description                           |
| ---------------- | ------------------------------------- |
| `-m <n>`         | Max results (default: 25)             |
| `--per-file <n>` | Matches per file (default: 1)         |
| `--compact`      | File paths only (like `grep -l`)      |
| `-s`, `--sync`   | Re-index changed files before search  |
| `-r`, `--reset`  | Reset index and re-index from scratch |

### Examples

```bash
osgrep "API rate limiting logic"
osgrep "error handling" --per-file 5
osgrep "user validation" --compact
```
