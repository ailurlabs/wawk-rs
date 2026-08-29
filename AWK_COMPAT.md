# wawk AWK Compatibility and Extensions

**Version**: 1.0.0
**Last Updated**: 2026-08-28

This document lists all POSIX AWK features supported by wawk, gawk extensions implemented, and wawk-specific extensions beyond traditional AWK.

---

## 1. POSIX AWK Feature Support

### 1.1 Pattern-Action Rules

| Feature | Status | Notes |
|---------|--------|-------|
| `pattern { action }` | ✅ Full | Standard rule syntax |
| `BEGIN { ... }` | ✅ Full | Runs before input processing |
| `END { ... }` | ✅ Full | Runs after all input processed |
| `/regex/` | ✅ Full | Regex pattern matching |
| `expr` (expression pattern) | ✅ Full | Conditional pattern |
| `pat1, pat2` (range) | ✅ Full | Range patterns with state tracking |
| Empty pattern (match all) | ✅ Full | Matches every record |
| `//` (empty regex) | ✅ Full | Matches every line (like gawk) |

### 1.2 Built-in Variables

| Variable | Status | Notes |
|----------|--------|-------|
| `NF` | ✅ Full | Number of fields in current record |
| `NR` | ✅ Full | Total number of records |
| `FS` | ✅ Full | Input field separator (default: space) |
| `RS` | ✅ Full | Input record separator (default: newline) |
| `OFS` | ✅ Full | Output field separator (default: space) |
| `ORS` | ✅ Full | Output record separator (default: newline) |
| `FILENAME` | ✅ Full | Current input filename |
| `FNR` | ✅ Full | Record number in current file |
| `ARGC` | ✅ Full | Argument count |
| `ARGV` | ✅ Full | Argument array |
| `OFMT` | ✅ Full | Output format for numbers (default: "%.6g") |
| `CONVFMT` | ✅ Full | Conversion format for numbers |
| `SUBSEP` | ✅ Full | Subscript separator for multi-dim arrays |
| `ERRNO` | ✅ Full | Error message string |
| `FPAT` | ✅ Full | Field pattern (gawk extension) |
| `ENVIRON` | ✅ Full | Environment variables (read-only) |

### 1.3 Built-in Functions

#### String Functions

| Function | Status | Notes |
|----------|--------|-------|
| `length(s)` | ✅ Full | String length (or array length) |
| `substr(s, m, n)` | ✅ Full | Substring extraction |
| `index(s, t)` | ✅ Full | Find position of substring |
| `split(s, a, fs)` | ✅ Full | Split string into array |
| `sub(r, t, s)` | ✅ Full | Substitute first match |
| `gsub(r, t, s)` | ✅ Full | Substitute all matches |
| `sprintf(fmt, ...)` | ✅ Full | Formatted string |
| `tolower(s)` | ✅ Full | Convert to lowercase |
| `toupper(s)` | ✅ Full | Convert to uppercase |
| `match(s, r)` | ✅ Full | Find regex match position |
| `patsplit(s, a, fs [, seps])` | ✅ Full | Split by pattern (gawk extension) |

#### Math Functions

| Function | Status | Notes |
|----------|--------|-------|
| `atan2(y, x)` | ✅ Full | Arctangent |
| `cos(x)` | ✅ Full | Cosine |
| `sin(x)` | ✅ Full | Sine |
| `exp(x)` | ✅ Full | Exponential |
| `log(x)` | ✅ Full | Natural logarithm |
| `sqrt(x)` | ✅ Full | Square root |
| `int(x)` | ✅ Full | Truncate to integer |
| `rand()` | ✅ Full | Random number [0,1) |
| `srand(seed)` | ✅ Full | Seed random number generator |
| `abs(x)` | ✅ Full | Absolute value (extension) |

#### Bitwise Functions (gawk extensions)

| Function | Status | Notes |
|----------|--------|-------|
| `and(v1, v2)` | ✅ Full | Bitwise AND |
| `or(v1, v2)` | ✅ Full | Bitwise OR |
| `xor(v1, v2)` | ✅ Full | Bitwise XOR |
| `lshift(v, c)` | ✅ Full | Left shift |
| `rshift(v, c)` | ✅ Full | Right shift |
| `compl(v)` | ✅ Full | Bitwise complement |

#### Time Functions (gawk extensions)

| Function | Status | Notes |
|----------|--------|-------|
| `systime()` | ✅ Full | Current time as epoch |
| `strftime(fmt, t)` | ✅ Full | Format time string |
| `mktime(datespec)` | ✅ Full | Parse date to epoch |

#### I/O Functions

| Function | Status | Notes |
|----------|--------|-------|
| `print` | ✅ Full | Print to stdout |
| `print > file` | ✅ Full | Redirect to file (truncate) |
| `print >> file` | ✅ Full | Redirect to file (append) |
| `print \| cmd` | ✅ Full | Pipe to command |
| `printf fmt, ...` | ✅ Full | Formatted print |
| `printf > file` | ✅ Full | Formatted redirect |
| `getline` | ✅ Full | Read next record |
| `getline var` | ✅ Full | Read into variable |
| `getline < file` | ✅ Full | Read from file |
| `getline var < file` | ✅ Full | Read from file into var |
| `getline \| cmd` | ✅ Full | Read from pipe |
| `close(file)` | ✅ Full | Close file or pipe |
| `fflush()` | ✅ Full | Flush output buffer |
| `system(cmd)` | ✅ Full | Execute shell command |
| `nextfile` | ✅ Full | Skip to next input file |

### 1.4 Operators

| Operator | Status | Notes |
|----------|--------|-------|
| `+ - * / %` | ✅ Full | Arithmetic |
| `^ **` | ✅ Full | Exponentiation |
| `= += -= *= /= %=` | ✅ Full | Assignment operators |
| `== != < <= > >=` | ✅ Full | Comparison |
| `&& \|\| !` | ✅ Full | Logical |
| `~ !~` | ✅ Full | Regex match/not-match |
| `++ --` | ✅ Full | Increment/decrement (pre and post) |
| `? :` | ✅ Full | Ternary conditional |
| `in` | ✅ Full | Array membership test |
| juxtaposition | ✅ Full | String concatenation |

### 1.5 Control Flow

| Statement | Status | Notes |
|-----------|--------|-------|
| `if (cond) ... else ...` | ✅ Full | Conditional |
| `while (cond) ...` | ✅ Full | While loop |
| `for (init; cond; incr) ...` | ✅ Full | For loop |
| `for (var in arr) ...` | ✅ Full | Array iteration |
| `do ... while (cond)` | ✅ Full | Do-while loop |
| `break` | ✅ Full | Exit loop |
| `continue` | ✅ Full | Continue loop |
| `next` | ✅ Full | Skip to next record |
| `nextfile` | ✅ Full | Skip to next file |
| `exit [expr]` | ✅ Full | Exit with status |
| `return [expr]` | ✅ Full | Return from function |

### 1.6 Data Types and Features

| Feature | Status | Notes |
|---------|--------|-------|
| User-defined functions | ✅ Full | `function name(params) { body }` |
| Associative arrays | ✅ Full | `arr[key] = value` |
| Multi-dimensional arrays | ✅ Full | `arr[i,j]` via SUBSEP |
| `delete arr[key]` | ✅ Full | Delete array element |
| `delete arr` | ✅ Full | Delete entire array |
| Regular expressions (ERE) | ✅ Full | Full ERE syntax |
| Field references `$1..$N` | ✅ Full | Dynamic field access |
| `$0` (whole record) | ✅ Full | Entire record |
| Backslash-newline continuation | ✅ Full | Line continuation |
| Comments (`#`) | ✅ Full | Line comments |
| Hex literals (`0xNN`) | ✅ Full | Hexadecimal numbers |
| String escapes (`\n \t \r \\ \"`) | ✅ Full | All standard escapes |
| Octal escapes (`\OOO`) | ✅ Full | Octal character codes |
| Hex escapes (`\xNN`) | ✅ Full | Hex character codes |

---

## 2. wawk Extensions Beyond AWK

### 2.1 PropertyTree-Native Access

wawk extends AWK with native structured data support via the PropertyTree model:

| Feature | Syntax | Example |
|---------|--------|---------|
| Object field access | `$.field` | `$.name` → `"Alice"` |
| Nested field access | `$.parent.child` | `$.address.city` → `"Berlin"` |
| Array positional access | `$1, $2, $3` | `$1` → first element |
| Auto-detection | Automatic | JSON input parsed automatically |
| Object/Array literals | `{...}`, `[...]` | `x = {"key": "value"}` |
| Dot access on expressions | `expr.field` | `(func()).field` |
| Index access on expressions | `expr[idx]` | `arr[0]` on array values |

**Example:**
```awk
# Input: {"name":"Alice","address":{"city":"Berlin"}}
{ print $.name, $.address.city }
# Output: Alice Berlin
```

### 2.2 Multi-Format Auto-Detection

wawk automatically detects and parses multiple input formats:

| Format | Detection | Priority | Serialization |
|--------|-----------|----------|---------------|
| JSON | `{...}` or `[...]` | 10 (highest) | ✅ Full |
| XML | `<?xml` or `<tag>` | 30 | ⚠️ Parse only |
| YAML | `---` document start | 40 | ⚠️ Parse only |
| CSV | Consistent comma columns | 50 | ✅ Full |

All formats are converted to the internal PropertyTree model for uniform access.

### 2.3 PropertyTree Universal Data Model

The PropertyTree is wawk's internal representation for hierarchical data:

```
PropertyTree
├── Null
├── Bool(bool)
├── Number(Integer(i64) | Float(f64))
├── String(String)
├── Array(Vec<PropertyTree>)
└── Object(Vec<(String, PropertyTree)>)  // ordered, preserves insertion order
```

### 2.4 Type System Extensions

| Function | Description |
|----------|-------------|
| `typeof(expr)` | Returns type name: "number", "string", "boolean", "null", "object", "array", "undefined" |
| `is_null(expr)` | Returns 1 if null, 0 otherwise |
| `is_object(expr)` | Returns 1 if object, 0 otherwise |
| `to_json(expr)` | Serialize value to JSON string |
| `from_json(str)` | Parse JSON string to value |

### 2.5 Plugin System (WIT Component Model)

wawk supports plugins via the WIT Component Model:

| Interface | Description |
|-----------|-------------|
| `external-functions` | Function dispatch: `call(name, args) -> option<string>` |
| `format-handler` | Format plugin: `detect`, `parse`, `serialize` |

**Plugin Features:**
- WebAssembly components (.wasm)
- Sandboxed execution
- O(1) function dispatch via index
- Dependency resolution
- Init phase support
- Any WIT-compatible language (Rust, C, Go, TypeScript)

### 2.6 Security Sandboxing

| Limit | Value | Description |
|-------|-------|-------------|
| `MAX_OUTPUT_BYTES` | 64 MB | Maximum output size |
| `MAX_CALL_DEPTH` | 256 | Maximum recursion depth |
| `MAX_EXPR_DEPTH` | 1024 | Maximum expression nesting |
| `MAX_FIELDS` | 100,000 | Maximum fields per record |
| `MAX_REGEX_PATTERN_LEN` | 4,096 | Maximum regex pattern length |
| `MAX_ARRAY_SIZE` | 1,000,000 | Maximum array entries |
| `MAX_PT_NESTING_DEPTH` | 64 | Maximum PropertyTree nesting |
| `MAX_PT_OBJECT_KEYS` | 10,000 | Maximum keys per object |
| `MAX_PT_KEY_LENGTH` | 1,000 | Maximum key length |
| `MAX_PT_ARRAY_LENGTH` | 100,000 | Maximum array length |
| `MAX_INPUT_SIZE` | 10 MB | Maximum lexer input size |

### 2.7 Performance Optimizations

| Optimization | Description |
|--------------|-------------|
| Zero-allocation hot paths | Reusable buffers for print, array keys, split parts |
| Fast integer formatting | `itoa` library (avoids `format!` overhead) |
| Fast float formatting | `ryu` library (avoids `format!` overhead) |
| Literal pattern fast-path | Substring search instead of regex engine |
| FxHashMap | Fast hashing for arrays and variables |
| Deferred field materialization | Byte ranges into line buffer |
| Regex compilation cache | LRU eviction, max 512 entries |
| Scope stack | Zero-copy variable scoping for functions |
| JSON skip optimization | Skip JSON detection when not needed |
| Pattern-aware field splitting | Only split fields when patterns/actions need them |

---

## 3. Comparison with Traditional AWK Implementations

| Feature | wawk | gawk | mawk | nawk |
|---------|------|------|------|------|
| POSIX compliance | ✅ | ✅ | ✅ | ✅ |
| WebAssembly | ✅ Native | ❌ | ❌ | ❌ |
| JSON access | ✅ Native | ❌ | ❌ | ❌ |
| Multi-format (XML/YAML/CSV) | ✅ | ❌ | ❌ | ❌ |
| Plugin system | ✅ WIT | ⚠️ Extensions | ❌ | ❌ |
| Security sandbox | ✅ | ❌ | ❌ | ❌ |
| Bitwise functions | ✅ | ✅ | ❌ | ❌ |
| Time functions | ✅ | ✅ | ❌ | ❌ |
| FPAT | ✅ | ✅ | ❌ | ❌ |
| patsplit | ✅ | ✅ | ❌ | ❌ |
| typeof | ✅ | ✅ | ❌ | ❌ |
| nextfile | ✅ | ✅ | ❌ | ⚠️ |
| Browser support | ✅ | ❌ | ❌ | ❌ |
| Edge runtime | ✅ | ❌ | ❌ | ❌ |

---

## 4. Unsupported / Not Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| `gensub()` | ❌ Not implemented | gawk extension |
| `asort()` | ❌ Not implemented | gawk extension |
| `asorti()` | ❌ Not implemented | gawk extension |
| `isarray()` | ❌ Not implemented | gawk extension |
| `bindtextdomain()` | ❌ Not implemented | i18n not needed in Wasm |
| `@include` | ❌ Not implemented | Use plugins instead |
| `@load` | ❌ Not implemented | Use WIT plugins instead |
| MPFR/GMP arbitrary precision | ❌ Not implemented | Uses f64 |
| XML serialization | ⚠️ Partial | Parse only |
| YAML serialization | ⚠️ Partial | Parse only |

---

## 5. Porting Guide

### From gawk to wawk

Most gawk programs work unchanged. Replace:
- `gensub()` → use `sub()`/`gsub()` or write user function
- `asort()`/`asorti()` → implement sorting in user function
- `@include "file"` → use WIT plugins

### From mawk/nawk to wawk

mawk/nawk programs are POSIX-compliant and work unchanged in wawk.
You gain access to gawk extensions (bitwise, time functions) and wawk extensions (JSON, multi-format).

---

## License

MIT OR Apache-2.0
