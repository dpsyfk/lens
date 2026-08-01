# WASM plugins

Lens plugins are explicitly installed WebAssembly modules. They run only when `--enable-plugins` is present and only after Lens applies its default redaction policy. Even a capture started with `--reveal` sends the plugin a separately redacted copy.

## Install and enable

```sh
lens plugin install --file ./slow-api.wasm \
  --name slow-api --plugin-version 1.0.0
lens plugin list
lens run --enable-plugins
lens plugin remove --name slow-api
```

Install never overwrites an existing name. Lens stores the module with a small manifest and verifies its SHA-256 before loading. The digest detects later modification; it does not establish publisher identity. Obtain plugins from a source you trust.

The default directory is the user's application-data directory. `LENS_PLUGIN_DIR` or `--plugin-dir` selects an explicit alternative. Lens never searches the current project directory and never auto-loads a module merely because it exists.

## ABI v1

ABI v1 is a core WebAssembly module with no imports and these exports:

```text
memory
lens_abi_version() -> i32                 # must return 1
lens_alloc(length: i32) -> i32            # input allocation
lens_process(pointer: i32, length: i32) -> i64
```

The process result packs the output pointer in the high 32 bits and output length in the low 32 bits. Input is UTF-8 JSON with schema version `1.0`, a redacted message summary/body, identifiers, direction, truncation, and sensitivity. Output is one UTF-8 annotation shown in the inspector and included in safe exports.

## Security and limits

- No imports means no WASI, filesystem, network, environment, clock, random, or process capability.
- Modules are limited to 4 MiB, linear memory to 8 MiB, input to 256 KiB, output to 4 KiB, and execution to 5,000,000 fuel units per call.
- Each call receives a new instance. Traps, invalid output, fuel exhaustion, and ABI failures are counted on the affected flow and do not stop forwarding.
- At most 32 annotations are retained per flow. Observation and store bounds still apply.
- Plugins cannot alter routes, traffic bytes, redaction policy, replay decisions, or certificates.

The sandbox reduces risk but does not make untrusted code harmless. Keep Lens and its WebAssembly runtime updated, and remove plugins you no longer use.
