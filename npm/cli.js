#!/usr/bin/env node
"use strict";

const fs = require("fs");

let _mod = null;
async function getMod() {
  if (!_mod) {
    _mod = require("./wawk.js");
    if (typeof _mod === "function") {
      await _mod();
      _mod = require("./wawk.js");
    }
  }
  return _mod;
}

function usage() {
  console.error("Usage: wawk [-F fs] [-v var=val] [-f scriptfile] [script] [file ...]");
  process.exit(1);
}

function readStdin() {
  try {
    return fs.readFileSync(0, "utf-8");
  } catch (_) {
    return "";
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) usage();

  let fieldSep = null;
  const vars = [];
  let scriptText = null;
  let scriptFile = null;
  const inputFiles = [];

  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "-F") {
      i++;
      if (i >= args.length) { console.error("wawk: -F requires an argument"); process.exit(1); }
      fieldSep = args[i];
    } else if (a.startsWith("-F") && a.length > 2) {
      fieldSep = a.slice(2);
    } else if (a === "-v") {
      i++;
      if (i >= args.length) { console.error("wawk: -v requires an argument"); process.exit(1); }
      vars.push(args[i]);
    } else if (a.startsWith("-v") && a.length > 2) {
      vars.push(a.slice(2));
    } else if (a === "-f") {
      i++;
      if (i >= args.length) { console.error("wawk: -f requires a filename"); process.exit(1); }
      scriptFile = args[i];
    } else if (a === "--help" || a === "-h") {
      usage();
    } else if (a === "--version") {
      const pkg = require("./package.json");
      console.log("wawk " + pkg.version);
      process.exit(0);
    } else if (scriptText === null && scriptFile === null) {
      scriptText = a;
    } else {
      inputFiles.push(a);
    }
    i++;
  }

  // Resolve script
  let script;
  if (scriptFile) {
    try {
      script = fs.readFileSync(scriptFile, "utf-8");
    } catch (e) {
      console.error("wawk: cannot open script file: " + scriptFile);
      process.exit(1);
    }
  } else if (scriptText) {
    script = scriptText;
  } else {
    console.error("wawk: no script provided");
    usage();
  }

  // Build -v assignments as AWK BEGIN prefix
  let varPrefix = "";
  for (const v of vars) {
    const eq = v.indexOf("=");
    if (eq > 0) {
      const name = v.substring(0, eq);
      const val = v.substring(eq + 1);
      const escaped = val.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
      varPrefix += "BEGIN { " + name + ' = "' + escaped + '" }\n';
    }
  }
  const fullScript = varPrefix + script;

  const mod = await getMod();

  // Execute
  let output;
  if (inputFiles.length > 0) {
    // Multi-file mode
    const filesJson = {};
    const argvEntries = [];
    for (const fname of inputFiles) {
      try {
        filesJson[fname] = fs.readFileSync(fname, "utf-8");
        argvEntries.push(fname);
      } catch (e) {
        console.error("wawk: cannot open input file: " + fname);
        process.exit(1);
      }
    }

    if (typeof mod.exec_awk_with_files === "function") {
      output = mod.exec_awk_with_files(
        fullScript,
        "",
        JSON.stringify(argvEntries),
        JSON.stringify(filesJson)
      );
    } else {
      // Fallback: concatenate all files
      let combined = "";
      for (const fname of inputFiles) {
        combined += fs.readFileSync(fname, "utf-8");
      }
      output = fieldSep
        ? mod.exec_awk_with_fs(fullScript, combined, fieldSep)
        : mod.exec_awk(fullScript, combined);
    }
  } else {
    // stdin mode
    const input = readStdin();
    output = fieldSep
      ? mod.exec_awk_with_fs(fullScript, input, fieldSep)
      : mod.exec_awk(fullScript, input);
  }

  // Write output
  if (output) {
    process.stdout.write(output);
  }
}

main().catch((e) => {
  console.error("wawk: " + (e.message || e));
  process.exit(1);
});
