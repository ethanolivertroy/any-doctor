import { spawn } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { fileURLToPath } from "url";
import { Cause, Effect, Exit, Schema } from "effect";
import { fixturesPathFor, modeArgs, RESULT_SENTINEL, SCAFFOLD_TODO, SEARCH_RESULT } from "./contract.js";
import { scanDoctorFile } from "./capabilities.js";
import { analysisStatus } from "./analysis.js";
import { unsafeRefusalLine } from "./report.js";
import { handleSearchLine } from "./search-host.js";
// The Runner: the single owner of the doctor-loader protocol. Everything
// that executes a doctor program — run, verify, meta, count — crosses this
// interface: the argv shapes (built from a Mode value), the sentinel
// framing, the timeout policy, and the typed failures. The parent side of
// Confinement lives here too (permission flags, the runtime-denial
// mapping); the Engine and the search host sit behind their own modules.
export class ProgramMissing extends Schema.TaggedError()("ProgramMissing", {
    programPath: Schema.String,
}) {
}
export class FixturesMissing extends Schema.TaggedError()("FixturesMissing", {
    programPath: Schema.String,
    fixturesPath: Schema.String,
}) {
}
export class ScaffoldIncomplete extends Schema.TaggedError()("ScaffoldIncomplete", {
    filePath: Schema.String,
}) {
}
export class DoctorCrashed extends Schema.TaggedError()("DoctorCrashed", {
    programPath: Schema.String,
    detail: Schema.String,
}) {
}
export class NoFramedResult extends Schema.TaggedError()("NoFramedResult", {
    programPath: Schema.String,
    stdout: Schema.String,
}) {
}
// The doctor references capabilities no doctor legitimately has (network,
// file writes, subprocesses, imports). This is a hard refuse: every execution
// path (run, verify, meta, count) passes through it, and there is no override.
// The typed error carries the capability set, so callers render the refusal
// from it — nobody re-scans to re-derive what this already knows.
export class DoctorUnsafe extends Schema.TaggedError()("DoctorUnsafe", {
    programPath: Schema.String,
    capabilities: Schema.Array(Schema.String),
    findings: Schema.Array(Schema.String),
}) {
}
export class RuntimeConfinementUnavailable extends Schema.TaggedError()("RuntimeConfinementUnavailable", {
    detail: Schema.String,
}) {
}
export function isRunnerError(e) {
    return e instanceof ProgramMissing || e instanceof FixturesMissing || e instanceof ScaffoldIncomplete
        || e instanceof DoctorCrashed || e instanceof NoFramedResult || e instanceof DoctorUnsafe || e instanceof RuntimeConfinementUnavailable;
}
export function describeRunnerError(e) {
    switch (e._tag) {
        case "ProgramMissing": return "no such doctor program: " + e.programPath;
        case "FixturesMissing": return "no fixtures found for this doctor — expected " + e.fixturesPath;
        case "ScaffoldIncomplete": return "unfinished scaffold placeholder in " + e.filePath
            + " — replace every " + SCAFFOLD_TODO + " marker before running or verifying";
        case "DoctorCrashed": return "doctor crashed:\n" + e.detail;
        case "NoFramedResult": return "doctor produced no framed result — stdout was:\n" + e.stdout;
        case "DoctorUnsafe": return "\ud83d\uded1 " + unsafeRefusalLine(path.basename(e.programPath), e.capabilities)
            + "\n  " + e.findings.join("\n  ");
        case "RuntimeConfinementUnavailable": return "cannot execute doctor safely: " + e.detail;
    }
}
// One line for listings — the broken-doctor warnings and failure parts —
// where the full detail belongs to describeRunnerError's renderers. Lives
// beside the error taxonomy so rendering rules for one type stay in one
// place.
export function causeSummaryLine(e) {
    if (e === undefined)
        return "invalid meta";
    if (e._tag === "DoctorCrashed")
        return e.detail.split("\n")[0];
    return describeRunnerError(e).split("\n")[0];
}
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const META_TIMEOUT_MS = 30 * 1000;
// Feature probe, run once per process: does this runtime know --permission?
// Runtimes without it degrade to the static gate alone. Exported so tests
// gate on the same answer the runner uses — no copied probes.
export function supportsPermissionModel() {
    return (probe !== null && probe !== void 0 ? probe : (probe = new Promise((resolve) => {
        const child = spawn(process.execPath, ["--permission", "-e", "0"], { stdio: "ignore" });
        child.on("error", () => resolve(false));
        child.on("close", (code) => resolve(code === 0));
    })));
}
let probe;
// Node's permission model is a required runtime boundary for doctor code.
// Read access is deliberately narrow: the any-doctor package itself, the
// doctor program, and only the run target or verification fixtures. There is
// no broad host read grant for a doctor to escape through a missed static
// check. --allow-worker is for the import guard's hook thread; the doctor
// cannot import Worker after confinement, and worker threads inherit every
// other denial. Network is not covered by Node's permission model, so the
// loader removes Node's builtin-module escape hatches before doctor code runs.
// Native addons are enabled only so the loader can initialize its trusted,
// package-owned analysis provider before it confines doctor code. The loader
// removes process.dlopen before importing the doctor, so doctor code cannot
// load an add-on of its own.
const PERMISSION_BASE = ["--permission", "--allow-addons", "--allow-worker", "--disable-warning=SecurityWarning"];
const canonicalPath = (value) => {
    try {
        return fs.realpathSync(value);
    }
    catch {
        return path.resolve(value);
    }
};
const PACKAGE_ROOT = canonicalPath(fileURLToPath(new URL("..", import.meta.url)));
// Exported so the loader tests can spawn children in exactly the
// configuration production creates — no fictional flag sets.
export async function permissionArgs(programPath, mode, verifyRoot) {
    if (!(await supportsPermissionModel())) {
        throw new Error("Node's --permission model is required (use a supported Node runtime)");
    }
    const readRoots = [PACKAGE_ROOT];
    const addReadRoot = (value) => {
        const root = canonicalPath(value);
        if (!readRoots.some(allowed => root === allowed || root.startsWith(allowed + path.sep))) {
            readRoots.push(root);
        }
    };
    if (mode.kind === "run")
        addReadRoot(mode.root);
    if (mode.kind === "verify") {
        if (verifyRoot === undefined)
            throw new Error("verification requires a dedicated sandbox root");
        addReadRoot(verifyRoot);
        addReadRoot(mode.fixtures);
        // Corpus fixtures are an explicit verification input, not inherited
        // ambient state. When configured, grant only that directory and forward
        // only its canonical path below.
        if (process.env.ANY_DOCTOR_CORPUS_ROOT)
            addReadRoot(process.env.ANY_DOCTOR_CORPUS_ROOT);
    }
    addReadRoot(programPath);
    // Node applies overlapping read grants in CLI order. Parents must precede
    // descendants; otherwise an explicitly named doctor inside its target can
    // shadow the target's recursive grant on Node 22.
    const readArgs = [...readRoots]
        .sort((a, b) => a.split(path.sep).length - b.split(path.sep).length)
        .map(root => `--allow-fs-read=${root}`);
    return mode.kind === "verify"
        ? [...PERMISSION_BASE, ...readArgs, `--allow-fs-write=${canonicalPath(verifyRoot)}`]
        : [...PERMISSION_BASE, ...readArgs];
}
// Exported with its table: Node's denial phrasings vary across versions,
// and what the refusal line names for an evading doctor depends on this
// mapping — it deserves direct tests, not coverage by e2e accident.
export function deniedByPermissionModel(stderr) {
    return /ErrAccessDenied|not allowed by the permission model|access to this api has been restricted/i.test(stderr);
}
export function denialCapability(stderr) {
    if (/--allow-fs-write/i.test(stderr))
        return "file write";
    if (/--allow-child-process/i.test(stderr))
        return "subprocess";
    if (/--allow-worker/i.test(stderr))
        return "worker";
    if (/--allow-addon/i.test(stderr))
        return "native addon";
    return "forbidden capability";
}
// A result frame can legitimately contain many findings. Keep enough room for
// a useful large scan while still making the parent memory bound explicit.
const MAX_LOADER_STREAM_BYTES = 16 * 1024 * 1024;
const MAX_SEARCH_REQUEST_BYTES = 64 * 1024;
const MAX_SEARCH_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_SEARCH_REQUESTS = 4096;
function confinedEnv(verifyRoot) {
    // Do not let arbitrary doctor code inspect credentials from developer or CI
    // environments. On Windows SystemRoot is needed for child process startup;
    // no other inherited value is necessary because the parent resolves Node by
    // absolute path and owns all search subprocesses.
    const env = process.platform === "win32" && process.env.SystemRoot
        ? { SystemRoot: process.env.SystemRoot }
        : {};
    if (verifyRoot !== undefined)
        env.ANY_DOCTOR_VERIFY_ROOT = verifyRoot;
    if (verifyRoot !== undefined && process.env.ANY_DOCTOR_CORPUS_ROOT) {
        env.ANY_DOCTOR_CORPUS_ROOT = canonicalPath(process.env.ANY_DOCTOR_CORPUS_ROOT);
    }
    return env;
}
function loaderCwd(programPath, mode) {
    if (mode.kind === "run")
        return path.resolve(mode.root);
    if (mode.kind === "verify")
        return path.dirname(path.resolve(mode.fixtures));
    return path.dirname(path.resolve(programPath));
}
function spawnLoader(programPath, mode, timeoutMs, nodeFlags, verifyRoot) {
    return new Promise((resolve) => {
        var _a, _b, _c;
        const loader = fileURLToPath(new URL("doctor-loader.mjs", import.meta.url));
        const child = spawn(process.execPath, [...nodeFlags, loader, ...modeArgs(mode, programPath)], {
            stdio: ["pipe", "pipe", "pipe", "pipe"],
            timeout: timeoutMs,
            cwd: loaderCwd(programPath, mode),
            env: confinedEnv(verifyRoot),
        });
        let stdout = "";
        let stderr = "";
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let limited = false;
        let limitReason = "";
        const stopForOutputLimit = (reason) => {
            if (limited)
                return;
            limited = true;
            limitReason = reason;
            child.kill("SIGKILL");
        };
        (_a = child.stdout) === null || _a === void 0 ? void 0 : _a.on("data", (c) => {
            stdoutBytes += c.length;
            if (stdoutBytes > MAX_LOADER_STREAM_BYTES)
                return stopForOutputLimit("stdout exceeded the 16 MiB output limit");
            stdout += c.toString("utf8");
        });
        (_b = child.stderr) === null || _b === void 0 ? void 0 : _b.on("data", (c) => {
            stderrBytes += c.length;
            if (stderrBytes > MAX_LOADER_STREAM_BYTES)
                return stopForOutputLimit("stderr exceeded the 16 MiB output limit");
            stderr += c.toString("utf8");
        });
        // fd 3 carries ctx.search requests; the search host answers on stdin.
        let pending = "";
        let searchRequests = 0;
        const requestChannel = child.stdio[3];
        requestChannel === null || requestChannel === void 0 ? void 0 : requestChannel.on("data", (c) => {
            var _a;
            if (limited)
                return;
            pending += c.toString("utf8");
            if (Buffer.byteLength(pending) > MAX_SEARCH_REQUEST_BYTES) {
                stopForOutputLimit("a search request exceeded the 64 KiB protocol limit");
                return;
            }
            let nl;
            while ((nl = pending.indexOf("\n")) !== -1) {
                const line = pending.slice(0, nl);
                pending = pending.slice(nl + 1);
                if (++searchRequests > MAX_SEARCH_REQUESTS) {
                    stopForOutputLimit(`the doctor exceeded the ${MAX_SEARCH_REQUESTS} search-request limit`);
                    return;
                }
                const response = handleSearchLine(line, mode, undefined, verifyRoot);
                if (response === null)
                    continue;
                const payload = SEARCH_RESULT + response + "\n";
                if (Buffer.byteLength(payload) > MAX_SEARCH_RESPONSE_BYTES) {
                    stopForOutputLimit("a search response exceeded the 16 MiB protocol limit");
                    return;
                }
                // Respect stdin backpressure. Pausing the request pipe prevents the
                // parent from accumulating arbitrary response bytes while the child
                // is slow (or deliberately refuses to read).
                if (((_a = child.stdin) === null || _a === void 0 ? void 0 : _a.write(payload)) === false) {
                    requestChannel.pause();
                    child.stdin.once("drain", () => requestChannel.resume());
                }
            }
        });
        (_c = child.stdin) === null || _c === void 0 ? void 0 : _c.on("error", () => { });
        child.on("error", () => resolve({ status: null, stdout, stderr: stderr + "(loader failed to start)" }));
        child.on("close", (status) => resolve({
            status,
            stdout,
            stderr: limited ? `${stderr}\nDoctor output limit exceeded: ${limitReason}` : stderr,
        }));
    });
}
function lastLines(s, n = 8) {
    return s.trim().split("\n").slice(-n).join("\n");
}
// A crash's REASON lives at the top of stderr ("Error: <why>"), the
// stack trails beneath it. Keeping only the tail showed frames and
// swallowed the reason — including the engine's "ships with any-doctor"
// explanation (review probe). Keep both ends: the leading lines that
// state the cause, the trailing lines that locate it.
function crashSummary(s) {
    const lines = s.trim().split("\n");
    if (lines.length <= 8)
        return lines.join("\n");
    return [...lines.slice(0, 3), "  …", ...lines.slice(-4)].join("\n");
}
// Loader frames are authored by our own doctor-loader — trusted construction.
// The guards below separate "a usable frame" from "not a frame"; they are not
// schema validation of the doctor contract.
const execLoader = (programPath, mode, timeoutMs = DEFAULT_TIMEOUT_MS) => Effect.gen(function* () {
    const abs = path.resolve(programPath);
    if (!fs.existsSync(abs)) {
        return yield* new ProgramMissing({ programPath: abs });
    }
    // The resolver hook guards ESM only. Reject CommonJS/ambiguous entrypoints
    // before they can invoke require(), leaving .mjs as the single executable
    // doctor format and preserving the import boundary below.
    if (path.extname(abs) !== ".mjs") {
        return yield* new DoctorUnsafe({
            programPath: abs,
            capabilities: ["module format"],
            findings: ["doctor programs must use the .mjs ESM format; CommonJS entrypoints are not confined"],
        });
    }
    if (fs.readFileSync(abs, "utf8").includes(SCAFFOLD_TODO)) {
        return yield* new ScaffoldIncomplete({ filePath: abs });
    }
    const gate = scanDoctorFile(abs);
    if (gate.red.length > 0) {
        return yield* new DoctorUnsafe({
            programPath: abs,
            capabilities: [...new Set(gate.red.map(f => f.capability))],
            findings: gate.red.map(f => `${f.capability}: ${f.detail}`),
        });
    }
    const verifyRoot = mode.kind === "verify"
        ? fs.mkdtempSync(path.join(os.tmpdir(), "any-doctor-verify-"))
        : undefined;
    try {
        const nodeFlags = yield* Effect.tryPromise({
            try: () => permissionArgs(abs, mode, verifyRoot),
            catch: (e) => new RuntimeConfinementUnavailable({ detail: e instanceof Error ? e.message : String(e) }),
        });
        const out = yield* Effect.tryPromise({
            try: () => spawnLoader(abs, mode, timeoutMs, nodeFlags, verifyRoot),
            catch: (e) => new DoctorCrashed({ programPath: abs, detail: String(e) }),
        });
        if (out.status !== 0) {
            if (deniedByPermissionModel(out.stderr)) {
                return yield* new DoctorUnsafe({
                    programPath: abs,
                    capabilities: [denialCapability(out.stderr)],
                    findings: ["the runtime refused a forbidden capability:", ...lastLines(out.stderr, 2).split("\n")],
                });
            }
            return yield* new DoctorCrashed({ programPath: abs, detail: crashSummary(out.stderr || "exit " + out.status) });
        }
        const lines = out.stdout.split("\n");
        // The last sentinel line wins. A doctor writing directly to
        // process.stdout can forge a frame — accepted under the bug-not-
        // adversary trust model (doctor programs are our own agents' output).
        const idx = lines.findLastIndex(l => l.startsWith(RESULT_SENTINEL));
        const stdout = out.stdout.slice(0, 500);
        if (idx === -1) {
            return yield* new NoFramedResult({ programPath: abs, stdout });
        }
        let frame;
        try {
            frame = JSON.parse(lines[idx].slice(RESULT_SENTINEL.length));
        }
        catch {
            return yield* new NoFramedResult({ programPath: abs, stdout });
        }
        if (frame === null || typeof frame !== "object") {
            return yield* new NoFramedResult({ programPath: abs, stdout });
        }
        return frame;
    }
    finally {
        if (verifyRoot !== undefined)
            fs.rmSync(verifyRoot, { recursive: true, force: true });
    }
});
// Frames decode by their declared kind — the contract's Frame union is the
// discriminator; the casts below are keyed to it, not blind.
const asRunResult = (frame) => Effect.gen(function* () {
    var _a;
    if (frame.kind !== "run" || !Array.isArray(frame.findings) || frame.meta === null || typeof frame.meta !== "object") {
        return yield* new NoFramedResult({ programPath: String((_a = frame.root) !== null && _a !== void 0 ? _a : ""), stdout: JSON.stringify(frame).slice(0, 500) });
    }
    const result = frame;
    // The parent IS the host, so capabilities are known here, not asked:
    // whether the identity engine could power this run — the data behind
    // "narrowed" rendering (D20 Stage 2).
    result.capabilities = { analysis: analysisStatus().available };
    return result;
});
const asVerifyResult = (frame) => Effect.gen(function* () {
    var _a;
    if (frame.kind !== "verify" || !Array.isArray(frame.results) || frame.meta === null || typeof frame.meta !== "object") {
        return yield* new NoFramedResult({ programPath: String((_a = frame.programPath) !== null && _a !== void 0 ? _a : ""), stdout: JSON.stringify(frame).slice(0, 500) });
    }
    return frame;
});
// ---- the public interface: plain async, typed failures thrown ----
//
// Effect is an implementation detail of this module. The public functions
// throw the tagged errors above (they extend Error, so callers get _tag
// matching and a stack); concurrency and composition stay inside.
const squash = (cause) => {
    const e = Cause.squash(cause);
    // Defects (interrupt/die) never occur in this module's code paths, but a
    // defect must not escape the typed channel.
    return isRunnerError(e) ? e : new DoctorCrashed({ programPath: "", detail: String(e) });
};
async function drain(effect) {
    const exit = await Effect.runPromiseExit(effect);
    return Exit.match(exit, {
        onFailure: (cause) => { throw squash(cause); },
        onSuccess: (value) => value,
    });
}
const runDoctorE = ({ programPath, targetDir, includeTests }) => Effect.flatMap(execLoader(programPath, { kind: "run", root: path.resolve(targetDir), includeTests }, DEFAULT_TIMEOUT_MS), asRunResult);
const verifyDoctorE = ({ programPath, fixturesPath }) => Effect.gen(function* () {
    const abs = path.resolve(programPath);
    const fixtures = path.resolve(fixturesPath !== null && fixturesPath !== void 0 ? fixturesPath : fixturesPathFor(abs));
    if (!fs.existsSync(fixtures)) {
        return yield* new FixturesMissing({ programPath: abs, fixturesPath: fixtures });
    }
    if (fs.readFileSync(fixtures, "utf8").includes(SCAFFOLD_TODO)) {
        return yield* new ScaffoldIncomplete({ filePath: fixtures });
    }
    const frame = yield* execLoader(abs, { kind: "verify", fixtures }, DEFAULT_TIMEOUT_MS);
    return yield* asVerifyResult(frame);
});
export async function runDoctor(options) {
    return drain(runDoctorE(options));
}
// The cohort primitive: every doctor runs as its own confined child
// through a bounded pool — doctors are CPU-bound parsers, and an
// unbounded fan-out contends with the machine's real work (4 measured
// faster than 9-wide on a busy 10-core laptop). Results keep input
// order; a crash is typed data (RunnerError) and never interrupts its
// siblings. Concurrency policy is execution policy — it lives here,
// beside the Doctor-run protocol, and the command layer consumes the
// facade. onProgress fires as each doctor settles (completion order,
// not input order) — the live spinner's fuel; nothing else may depend
// on its timing.
export const DOCTOR_POOL_SIZE = 4;
export async function runDoctorCohort(options, onProgress) {
    const exits = await Effect.runPromise(Effect.forEach(options, (o) => Effect.tap(Effect.exit(runDoctorE(o)), (exit) => Effect.sync(() => {
        var _a;
        if (onProgress === undefined)
            return;
        const ok = Exit.isSuccess(exit);
        onProgress({
            total: options.length,
            programPath: o.programPath,
            ok,
            durationMs: ok ? ((_a = exit.value.durationMs) !== null && _a !== void 0 ? _a : 0) : 0,
        });
    })), {
        concurrency: Math.max(1, Math.min(DOCTOR_POOL_SIZE, options.length)),
    }));
    return exits.map((exit, i) => Exit.match(exit, {
        onSuccess: (result) => ({ ok: true, options: options[i], result }),
        onFailure: (cause) => ({ ok: false, options: options[i], cause: squash(cause) }),
    }));
}
export async function verifyDoctor(options) {
    return drain(verifyDoctorE(options));
}
// A doctor whose meta cannot be read is data (a broken doctor), not a
// failure: metaDoctor never throws, it returns { meta: null, error }.
export async function metaDoctor({ programPath }) {
    const frame = await Effect.runPromise(Effect.flatMap(Effect.exit(execLoader(programPath, { kind: "meta" }, META_TIMEOUT_MS)), (exit) => Effect.succeed(Exit.match(exit, {
        onFailure: (cause) => ({ meta: null, cause: squash(cause) }),
        onSuccess: (f) => ({
            meta: f.kind === "meta" && f.meta !== null && typeof f.meta === "object" ? f.meta : null,
        }),
    }))));
    return frame;
}
