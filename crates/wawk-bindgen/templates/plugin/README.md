# wawk Plugin Template

This template provides the scaffolding for creating a new wawk plugin.

## Plugin Convention

Every wawk plugin implements the `wawk:plugins/external-functions` interface:

### `__meta__` — Plugin Metadata (required)

Returns a JSON string with plugin information:

```json
{
    "name": "wawk-myplugin",
    "version": "0.1.0",
    "description": "My awesome plugin",
    "requires": []
}
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Plugin identity (used for dependency resolution and logging) |
| `version` | Yes | Semver version string |
| `requires` | No | Dependencies on other plugins (e.g., `["wawk-other"]`) |
| `description` | No | Human-readable description |

### Function Dispatch

The host calls `call(name, args)` for each unknown AWK function. Return:
- `Some(result)` — your plugin handled the function
- `None` — your plugin does not handle this function (try next plugin)

## Plugin Dependencies

Plugins can depend on other plugins by declaring them in `requires`:

```json
{
    "name": "wawk-myplugin",
    "version": "0.1.0",
    "requires": ["wawk-other"]
}
```

The host resolves dependencies and loads plugins in the correct order.
If a dependency is missing, the plugin is silently skipped (warning logged).

## Creating a New Plugin

1. Copy this `templates/plugin/` directory
2. Replace `PLUGINNAME` with your plugin name
3. Replace `PLUGIN_DESCRIPTION` with a description
4. Implement your functions in the `plugin_call()` match block
5. Add `"requires": [...]` to `__meta__` if your plugin depends on others
6. Build: `cargo build --target wasm32-unknown-unknown --release`

## Testing

```bash
cargo test
```

## Examples

| | Standalone Plugin | Plugin with Dependencies |
|---|---|---|
| `requires` | `[]` (empty) | `["wawk-other"]` |
| Dependency resolution | Loaded independently | Host loads dependencies first |
| Works without dependencies | Yes | No (silently skipped) |
| Example | wawk-hello | wawk-hello |
