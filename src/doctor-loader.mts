import { pathToFileURL } from "url";
import * as fs from "fs";
import * as path from "path";
import { register } from "node:module";
import { runOnce, certify, ClaimContractViolation } from "./certify.js";
import type { DoctorModule } from "./certify.js";
import * as contract from "./contract.js";
import type { Mode } from "./contract.js";
import { analysisStatus } from "./analysis.js";

// The doctor loader: the child process every doctor program runs inside.
// It owns the Doctor-run choreography — decode the Mode, confine the
// process, import the doctor, frame the result — and nothing else. Verify
// mode's policies (claim contract, fixture gate, corpora, probes) live in
// the Certification harness; the runner owns the protocol on the parent
// side; this file is the other end.

// The confinement prologue: a doctor's process has no network (the globals
// are deleted before any doctor code can run) and may not import anything
// (a resolve hook refuses every resolution that is not the loader's own).
// Ordering is load-bearing: this must run AFTER this module's own imports
// resolve (certify, contract — which is why they are static imports above)
// and BEFORE the doctor import below. Exported so the choreography has a
// direct test seam instead of being provable only end-to-end.
export function confineProcess(): void {
  const g = globalThis as Record<string, unknown>;
  delete g.fetch;
  try { delete g.WebSocket; } catch { /* already absent */ }
  // ESM resolution hooks cannot intercept process.getBuiltinModule(), which
  // bypasses import resolution entirely. Remove public module-loading escape
  // hatches before importing doctor code. The loader initializes its trusted
  // native parser first, then removes process.dlopen so doctor code cannot
  // load an add-on of its own. The doctor only receives ctx.
  const runtime = process as unknown as Record<string, unknown>;
  for (const name of ["getBuiltinModule", "binding", "_linkedBinding", "dlopen", "mainModule"]) {
    try {
      Object.defineProperty(runtime, name, { value: undefined, configurable: false, writable: false });
    } catch {
      try { runtime[name] = undefined; } catch { /* unavailable on this runtime */ }
    }
  }
  // This hook is the import boundary for the untrusted module. Continuing
  // without it would make a computed dynamic import a network escape, so a
  // runtime that cannot install it must fail before doctor code is loaded.
  register(new URL("./import-guard.mjs", import.meta.url));
}

const USAGE = "usage: doctor-loader.mjs <program.mjs> <root> [--include-tests] | <program.mjs> --verify <fixtures.mjs> | <program.mjs> --meta";

const SEVERITIES = new Set(["error", "warning", "info"]);

function validateMeta(mod: DoctorModule): void {
  const m = mod.meta as Record<string, unknown> | undefined;
  const problems: string[] = [];
  if (!m || typeof m !== "object") problems.push("missing meta export");
  if (m && typeof m.id !== "string") problems.push("meta.id must be a string");
  if (m && typeof m.description !== "string") problems.push("meta.description must be a string");
  if (m && !SEVERITIES.has(String(m.severity))) problems.push(`meta.severity must be one of error|warning|info — got ${JSON.stringify(m.severity)}`);
  if (problems.length) {
    console.error("invalid doctor meta: " + problems.join("; "));
    process.exit(3);
  }
}

async function main(): Promise<void> {
  // Decode before confinement so unsupported entrypoints can be rejected
  // without loading any doctor code. The .mjs restriction is essential:
  // module.register() hooks guard ESM resolution, not CommonJS require().
  const decoded = contract.decodeLoaderArgs(process.argv.slice(2));
  if (decoded === null) {
    console.error(USAGE);
    process.exit(2);
  }
  const prog = decoded.program;
  const mode: Mode = decoded.mode;
  if (path.extname(prog) !== ".mjs") {
    console.error("doctor programs must use the .mjs ESM format; CommonJS entrypoints are not confined");
    process.exit(3);
  }

  // Load the package-owned parser before removing native-loading APIs. This
  // keeps semantic checks available without granting that capability to a
  // doctor module imported below.
  analysisStatus();
  confineProcess();

  const mod = (await import(pathToFileURL(prog).href)) as DoctorModule;
  if (typeof mod.doctor !== "function") {
    console.error("doctor program must export `doctor(ctx)` — got: " + Object.keys(mod).join(", "));
    process.exit(3);
  }
  validateMeta(mod);

  const originalLog = console.log;
  console.log = (...args: unknown[]) => { process.stderr.write(args.map(a => String(a)).join(" ") + "\n"); };

  try {
    if (mode.kind === "meta") {
      process.stdout.write("\n" + contract.RESULT_SENTINEL + JSON.stringify({
        protocolVersion: contract.PROTOCOL_VERSION,
        kind: "meta",
        meta: mod.meta,
      }) + "\n");
    } else if (mode.kind === "run") {
      const result = await runOnce(mode.root, mod, { includeTests: contract.includeTestsFor(mode) });
      process.stdout.write("\n" + contract.RESULT_SENTINEL + JSON.stringify(result) + "\n");
    } else {
      const fixturesMod = (await import(pathToFileURL(mode.fixtures).href)) as { fixtures?: unknown };
      const fixtures = fixturesMod.fixtures;
      if (!Array.isArray(fixtures)) {
        console.error("fixture module must export `fixtures` (array) — got: " + Object.keys(fixturesMod).join(", "));
        process.exit(3);
      }
      let results;
      try {
        results = await certify(mod, fixtures as contract.Fixture[]);
      } catch (e) {
        if (e instanceof ClaimContractViolation) {
          console.error(e.message);
          process.exit(3);
        }
        throw e;
      }
      process.stdout.write("\n" + contract.RESULT_SENTINEL + JSON.stringify({
        protocolVersion: contract.PROTOCOL_VERSION,
        kind: "verify",
        meta: mod.meta,
        results,
      }) + "\n");
    }
  } finally {
    console.log = originalLog;
  }
}

// Direct-invocation guard: importing this module (tests, future tooling)
// never executes a Doctor run — the script body runs only when spawned.
const invokedDirectly = (() => {
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();

try {
  if (invokedDirectly) await main();
} catch (e) {
  console.error(e instanceof Error && e.stack ? e.stack : String(e));
  process.exit(1);
}
