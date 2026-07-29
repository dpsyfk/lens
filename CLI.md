# CLI Design Backlog

> **Status:** This is a product-design document, not the current command reference. The implemented commands are `run`, `doctor`, `cert`, `quickstart`, and `replay`; use `lens --help` for their exact flags. Commands such as `inspect`, `record`, standalone `export`, `benchmark`, `config`, and `completions` remain proposals unless promoted into the user guide.

## Purpose
Lens is a developer tool, so the CLI is the product's primary interface, not a thin wrapper around internal APIs. The command set must be easy to remember, safe by default, and predictable across platforms.

This document describes the intended long-term UX contract. Sections labeled as current reflect source behavior; other sections remain design backlog.

## CLI Philosophy

### Principles
- One command, one job.
- Safe defaults first, explicit escape hatches second.
- Interactive output for humans, structured output for automation.
- The same core concepts should appear everywhere: flows, messages, redaction, replay, config, and diagnostics.
- Commands should explain what they are doing when they might affect trust, privacy, or network traffic.

### Trade-offs
- A richer CLI takes more design discipline than a handful of ad hoc flags.
- Explicit commands reduce magic, but they make the behavior understandable and scriptable.
- The tool should feel calm rather than clever; that is slower to design, but easier to trust.

## Global Shape

### Command family
- `lens run`
- `lens inspect`
- `lens record`
- `lens replay`
- `lens doctor`
- `lens benchmark`
- `lens export`
- `lens config`

### Default command
- If the user runs `lens` with no subcommand, behave like `lens run`.
- Trade-off: this is convenient for interactive use, but it must be documented clearly so automation does not accidentally start a live session.

### Global options
- `--config <path>`: use a specific config file.
- `--profile <name>`: select a named config profile.
- `--json`: emit machine-readable output when the command supports it.
- `--quiet`: reduce nonessential output.
- `--verbose`: increase diagnostic detail, repeatable.
- `--no-color`: disable ANSI color.
- `--help`: print command help.
- `--version`: print the version.

### Trade-offs
- Global flags make the CLI consistent, but they must not override command-specific intent in surprising ways.
- `--json` is valuable for automation, but not every command has a useful structured form.
- `--verbose` should add context, not noise.

## Command: `lens run`

### Intent
Start the live proxy and UI for day-to-day debugging.

### Responsibilities
- Start the capture session.
- Resolve config and trust state.
- Launch the interactive TUI unless headless mode is requested.
- Forward traffic while capturing flows.
- Redact sensitive material by default.

### Suggested flags
- `--listen <addr:port>`: bind address for the proxy.
- `--mode <explicit|transparent>`: choose how traffic reaches Lens.
- `--upstream-proxy <url>`: chain to another proxy.
- `--protocols <list>`: enable specific decoders.
- `--reveal`: disable redaction after a loud warning.
- `--max-flows <n>`: cap in-memory history.
- `--max-body <bytes>`: cap captured payload size.
- `--headless`: run without the TUI.
- `--export <path>`: write captured data while the session runs.

### UX behavior
- On startup, show a short status summary: mode, listen address, redaction state, config profile, and trust state.
- If a trust-store or CA step is required, explain why before proceeding.
- If the user is in TTY mode, open the interactive flow map first.
- If the session cannot safely begin, fail early with a clear reason.

### Trade-offs
- `run` is the most powerful command, so it risks becoming overloaded.
- Keeping it the default improves discoverability, but the command must stay focused on live capture rather than turning into a generic subcommand bucket.
- Headless mode is useful for CI and long-running capture jobs, but it should not compromise the interactive story.

### Example
```text
lens run --mode explicit --listen 127.0.0.1:8888
```

## Command: `lens inspect`

### Intent
Open a specific flow, message, or export artifact and inspect it in a structured way.

### Responsibilities
- Locate a target by flow ID, request ID, selector, or file path.
- Render the request/response details with redaction preserved unless explicitly overridden.
- Let the user browse headers, metadata, bodies, and timing.

### Suggested flags
- `--flow <id>`: inspect a specific flow.
- `--message <id>`: inspect one message.
- `--source <path>`: inspect from an export file.
- `--raw`: show captured bytes with minimal normalization.
- `--reveal`: show sensitive fields after explicit confirmation.
- `--format <human|json>`: choose output mode.

### UX behavior
- Default to a human-readable inspector view.
- When the target is ambiguous, present a short selector list rather than failing silently.
- If the source is offline data, make that clear in the header.

### Trade-offs
- A dedicated inspect command keeps `run` from becoming a data browser.
- It is more work than simply opening everything inside `run`, but it provides a cleaner mental model.

### Example
```text
lens inspect --flow flow_01H... --reveal
```

## Command: `lens record`

### Intent
Capture traffic into a durable artifact for later analysis or sharing.

### Responsibilities
- Start a capture session with recording enabled.
- Write a local artifact while maintaining the live experience.
- Allow explicit limits for size, duration, and event types.

### Suggested flags
- `--output <path>`: destination artifact.
- `--format <jsonl|json|har>`: output format.
- `--duration <time>`: stop after a fixed period.
- `--until-exit`: stop when the tracked app exits.
- `--include <filters>`: limit what gets recorded.
- `--exclude <filters>`: omit selected flows or protocols.

### UX behavior
- Record should be explicit that it creates an artifact, not just a live session.
- The command should summarize what was recorded and what was omitted.
- If the file already exists, require a deliberate overwrite decision.

### Trade-offs
- Recording is useful for reproducibility, but it introduces privacy and storage concerns.
- Exporting from the live session could have been enough, but a dedicated command makes the intent obvious.

### Example
```text
lens record --output ./captures/login-flow.jsonl --format jsonl
```

## Command: `lens replay`

### Intent
Reissue a captured request or session against an upstream target.

### Current responsibilities
- Load a bounded JSON or JSONL snapshot.
- Select one HTTP/1 flow and one one-based request index.
- Reconstruct binary-safe headers and body from the stored, already-redacted representation.
- Preview against an explicit target without network activity by default.
- Execute only after every applicable risk is acknowledged.

### Current flags
- `--input <path>`: source capture; required.
- `--flow <id>`: select a flow when more than one HTTP flow exists.
- `--request <n>`: one-based request in the flow; default 1.
- `--target <origin>`: explicit HTTP(S) origin; required.
- `--execute`: send the reviewed request.
- `--allow-unsafe`: permit methods that may change state.
- `--allow-secrets`: permit a reveal-mode capture.
- `--allow-redacted`: permit literal redaction placeholders.
- `--allow-remote`: permit a non-loopback target.
- `--timeout-ms <n>`: request deadline.

### UX behavior
- Replay is preview-only by default in every environment.
- Header values and bodies are never printed in the preview.
- Truncated and legacy text-only requests cannot execute.
- Hop-by-hop headers are stripped and redirects are not followed.
- Response comparison becomes unavailable instead of guessing when capture fidelity is insufficient.

### Trade-offs
- Replay is a high-value debugging tool, but it is also the most likely command to cause side effects.
- Requiring explicit targets and previews makes it safer, though slightly slower.

### Example
```text
lens replay --input ./captures/login-flow.jsonl --flow 12 \
  --target http://127.0.0.1:8080
```

## Command: `lens doctor`

### Intent
Diagnose whether the environment is ready to use Lens.

### Responsibilities
- Check config resolution.
- Validate trust store and CA state.
- Verify port availability.
- Check platform limitations.
- Report decoder and plugin availability.

### Suggested flags
- `--json`: structured diagnostics.
- `--check trust`: focus on certificate setup.
- `--check network`: focus on bind and routing readiness.
- `--check config`: focus on config resolution.
- `--check all`: run every check.

### UX behavior
- Output should be action-oriented: what is wrong, why it matters, and how to fix it.
- Warnings should be clearly separated from failures.
- If the environment is already healthy, say that plainly.

### Trade-offs
- This command adds a maintenance burden because every new subsystem needs a diagnostic path.
- The benefit is huge: users can self-serve instead of guessing at setup failures.

### Example
```text
lens doctor --check all
```

## Command: `lens benchmark`

### Intent
Measure Lens behavior and protect performance over time.

### Responsibilities
- Run built-in benchmark scenarios.
- Compare current results to a baseline when available.
- Report regression or improvement trends.

### Suggested flags
- `--suite <name>`: select a benchmark set.
- `--baseline <path>`: compare against stored results.
- `--output <path>`: write results to disk.
- `--json`: emit structured results.
- `--repeat <n>`: run multiple samples.
- `--allow-regression <pct>`: set a threshold for reporting.

### UX behavior
- Benchmark output should be stable and easy to diff.
- The command should distinguish noise from real regression.
- It should explain when results are not statistically strong enough.

### Trade-offs
- Performance tooling is essential, but it is not a first-run user workflow.
- A separate command prevents benchmark concerns from leaking into the core capture flow.

### Example
```text
lens benchmark --suite proxy-throughput --baseline ./benchmarks/baseline.json
```

## Command: `lens export`

### Intent
Turn captured data into a portable artifact for sharing, archiving, or downstream analysis.

### Responsibilities
- Export flows, messages, and metadata.
- Preserve redaction state unless reveal was explicitly requested.
- Support multiple output formats.

### Suggested flags
- `--input <path>`: source session or artifact.
- `--output <path>`: destination file.
- `--format <jsonl|json|har|csv>`: export format.
- `--flows <selector>`: limit exported flows.
- `--messages <selector>`: limit exported messages.
- `--reveal`: include sensitive fields after confirmation.
- `--pretty`: make JSON more readable.

### UX behavior
- Export should say exactly what was exported and what was excluded.
- It should refuse accidental overwrite unless the user opts in.
- If the export may contain secrets, the warning should be visible and specific.

### Trade-offs
- Export is a broad command because different users need different downstream formats.
- The benefit of one command is discoverability; the cost is keeping the format surface coherent.

### Example
```text
lens export --input ./captures/session.jsonl --format har --output ./out/session.har
```

## Command: `lens config`

### Intent
Inspect, validate, and manage Lens configuration.

### Responsibilities
- Show the resolved config.
- Explain which layer supplied each value.
- Validate config files.
- Optionally write or unset values in a controlled way.

### Suggested subcommands
- `lens config show`
- `lens config validate`
- `lens config diff`
- `lens config set`
- `lens config unset`
- `lens config path`

### Suggested flags
- `--json`: structured output.
- `--profile <name>`: inspect a specific profile.
- `--effective`: show the final merged result.
- `--source`: include provenance for each field.

### UX behavior
- The `show` command should reveal the effective config, not just one file, because precedence matters.
- `validate` should fail with the smallest useful error message possible.
- `set` and `unset` should be cautious and explicit because they modify user state.

### Trade-offs
- Config inspection is indispensable, but config mutation can become a side effect trap.
- Keeping read and write operations in the same family helps discoverability, but the subcommands must remain sharply separated.

### Example
```text
lens config show --effective --source
```

## Help Output Design

### Overall style
Help text should answer three questions fast:
- What does this command do?
- What are the most important flags?
- What is the safest example to copy first?

### Formatting rules
- Put the one-line summary immediately under the command name.
- Group flags into logical clusters: connection, capture, privacy, output, and diagnostics.
- Show defaults inline when they matter.
- Keep examples short and realistic.
- Prefer plain language over implementation jargon.

### Example structure
```text
lens run
Start a live capture session and open the TUI.

USAGE:
  lens run [OPTIONS]

OPTIONS:
  --mode <explicit|transparent>    How traffic reaches Lens
  --listen <addr:port>             Listen address [default: 127.0.0.1:8888]
  --reveal                         Disable redaction after warning
  --headless                       Run without the TUI

EXAMPLES:
  lens run --mode explicit
  lens run --mode transparent --listen 127.0.0.1:8888
```

### Trade-offs
- Rich help output is a maintenance cost, but it is one of the fastest ways to reduce user confusion.
- Good help text often prevents support tickets before they exist.

## Error Message Design

### Principles
- Say what failed.
- Say why it matters.
- Say how to fix it.
- Avoid blaming the user.
- Avoid stack traces in normal CLI failures.

### Preferred style
- Include the command name in the error when helpful.
- Use concrete paths, ports, and values.
- Offer the next action where possible.
- Keep redaction errors distinct from transport errors and config errors.

### Examples
- `lens run: port 8888 is already in use. Try --listen 127.0.0.1:8890.`
- `lens replay: capture file not found: ./captures/login.jsonl`
- `lens doctor: trust store installation failed. Run this command with permission to update the local CA.`
- `lens export: refusing to overwrite ./out/session.jsonl. Pass --force to replace it.`

### Trade-offs
- Friendly messages take more design work than generic ones.
- The payoff is high: the tool becomes self-explanatory in failure states, which is where most real usage happens.

## UX Safety Rules
- Redaction is on by default.
- Dangerous actions require explicit confirmation or a clear non-interactive opt-in.
- Replay should default to dry-run behavior when ambiguity exists.
- Export should never silently reveal secrets.
- Diagnostics should be more helpful than alarming.

## Examples by Workflow

### First-time user
```text
lens doctor
lens run --mode explicit --listen 127.0.0.1:8888
```

### Live debugging
```text
lens run
lens inspect --flow flow_01H...
```

### Reproducibility
```text
lens record --output ./captures/session.jsonl
lens replay --input ./captures/session.jsonl --dry-run
```

### Sharing safely
```text
lens export --input ./captures/session.jsonl --format json --output ./out/session.json
```

### Performance work
```text
lens benchmark --suite proxy-throughput
```

## Final Position
The CLI should feel like a small set of dependable verbs rather than a giant option matrix. The verbs are intentionally human: run, inspect, record, replay, doctor, benchmark, export, config. That gives the tool a stable mental model and leaves room for future growth without making the first version feel crowded.
