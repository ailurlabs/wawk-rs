@echo off
REM wawk — CLI wrapper for wasmtime (Windows)
REM Usage: wawk [args...] — same as: wasmtime wawk.wasm [args...]
wasmtime "%~dp0wawk.wasm" %*
