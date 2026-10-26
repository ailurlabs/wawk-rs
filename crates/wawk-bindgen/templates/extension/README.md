# wawk Extension Template

This template provides the scaffolding for creating a new wawk extension.

## Extension Convention

Every wawk extension implements the `wawk:extensions/extension-functions` interface:

### `__meta__` — Extension Metadata (required)

Returns a JSON string with extension information:

```json
{
    "name": "wawk-myextension",
    "version": "0.1.0",
    "description": "My awesome extension",
    "requires": []
}
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Extension identity (used for dependency resolution and logging) |
| `version` | Yes | Semver version string |
| `requires` | No | Dependencies on other extensions (e.g., `["wawk-other"]`) |
| `description` | No | Human-readable description |

### Function Dispatch

The host calls `call(name, args)` for each unknown AWK function. Return:
- `Some(result)` — your extension handled the function
- `None` — your extension does not handle this function (try next extension)

## Extension Dependencies

Extensions can depend on other extensions by declaring them in `requires`:

```json
{
    "name": "wawk-myextension",
    "version": "0.1.0",
    "requires": ["wawk-other"]
}
```

The host resolves dependencies and loads extensions in the correct order.
If a dependency is missing, the extension is silently skipped (warning logged).

## Creating a New Extension

1. Copy this `templates/extension/` directory
2. Replace `EXTENSIONNAME` with your extension name
3. Replace `EXTENSION_DESCRIPTION` with a description
4. Implement your functions in the `extension_call()` match block
5. Add `"requires": [...]` to `__meta__` if your extension depends on others
6. Build: `cargo build --target wasm32-unknown-unknown --release`

## Testing

```bash
cargo test
```

## Examples

| | Standalone Extension | Extension with Dependencies |
|---|---|---|
| `requires` | `[]` (empty) | `["wawk-other"]` |
| Dependency resolution | Loaded independently | Host loads dependencies first |
| Works without dependencies | Yes | No (silently skipped) |
| Example | wawk-hello | wawk-hello |
