# SecureCode

**SecureCode** is a security-hardened fork of [OpenCode](https://github.com/anomalyco/opencode) built for running AI coding agents locally with **OS-kernel-enforced directory write confinement** on Windows and **Pre-LLM Secret Redaction (DLP)**.

Instead of relying solely on application-level permission prompts or path-string checks, SecureCode enforces boundaries directly at the Windows Security Reference Monitor (SRM) and at the LLM network/tool boundaries.

---

## Security Architecture

### 1. Windows OS-Level Directory Write Confinement
Every shell command and out-of-workspace file write attempt is confined to the active session directory (`location.directory`) at the **Windows Kernel level** — without requiring Administrator privileges, WSL2, or containers.

* **Restricted Access Token (`WRITE_RESTRICTED`):** Child processes are spawned via `CreateProcessAsUserW` using `CreateRestrictedToken` (`DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED`) with a deterministic per-workspace synthetic capability SID (`S-1-5-99-...`).
* **Per-Session NTFS DACL:** An inheritable `(OI)(CI)` Modify ACE for the session's synthetic SID is applied strictly to the active session directory and `<sessionDir>/.opencode/tmp`. Because no other path on disk carries this ACE, the Windows kernel (`SeAccessCheck` / `NtCreateFile`) rejects any write outside the session directory with `STATUS_ACCESS_DENIED` (`0xC0000022`).
* **DLL & Runtime Compatibility:** Updates `TokenDefaultDacl` via `SetTokenInformation` so PowerShell (`pwsh.exe` / `powershell.exe`), Git Bash, Node.js, and .NET runtimes initialize cleanly under `WRITE_RESTRICTED` without `0xC0000142` crashes.
* **Windows Job Objects:** Binds spawned process trees to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job Object so child processes cannot escape or outlive the session.
* **Realpath & Worktree Lockdown:** Resolves symlinks and NTFS junctions via `fs.realpathSync` and restricts internal access strictly to `location.directory` (preventing parent Git worktree traversal).
* **Environment Redirection:** Redirects `TEMP`, `TMP`, `TMPDIR`, `HOME`, `USERPROFILE`, `NPM_CONFIG_CACHE`, and `BUN_INSTALL_CACHE_DIR` into `<sessionDir>/.opencode/tmp` so toolchains function normally inside the sandbox.

#### Verified Enforcement Scope (Windows)
| Operation Outside Session Directory | Result |
| :--- | :--- |
| Create / write / append file (`shell` or `write`/`edit` tools) | **Blocked** (`Access Denied` / `UnauthorizedAccessException`) |
| Write to parent directory (`..\`) inside the same Git repo | **Blocked** |
| Nested grandchild process writes (`cmd` -> `powershell`) | **Blocked** (restricted token inherited) |
| Write through an NTFS Junction (`mklink /J`) pointing outside | **Blocked** (kernel checks target DACL) |
| Registry modifications (`reg add HKCU\...`) | **Blocked** (`Access is denied`) |

> **Scope note:** `WRITE_RESTRICTED` enforces **write integrity** (preventing unauthorized file/registry creation or modification outside the session directory). Global reads and outbound network access remain permitted so installed compilers, runtimes, and package managers continue to operate.

---

### 2. Pre-LLM Secret Redaction (DLP)
SecureCode prevents API keys, tokens, passwords, and private keys from leaving your machine to external LLM providers or being persisted in plaintext in session history.

Redaction runs at **two mandatory chokepoints**:
1. **Tool Output Boundary (`packages/core/src/tool/runtime.ts`):** Every tool result (`read`, `shell`, `grep`, `webfetch`, MCP tools) is scanned and masked before entering session history.
2. **Pre-Network Model Gate (`packages/core/src/session/model-request.ts`):** Every `system` prompt and `messages` payload is recursively scanned right before `ai.request(...)` dispatches to `LLMClient.Service`, catching secrets even if pasted directly into a user prompt.

#### Detection Layers (`packages/core/src/dlp/secret-redactor.ts`)
* **Layer 1 — Provider & Format Signatures:** 30+ patterns including AWS (`AKIA...`), GitHub (`ghp_`, `github_pat_`), GitLab, OpenAI/Anthropic (`sk-...`), Google (`AIza...`), Stripe (`sk_live_`/`rk_live_`), Slack, Discord, Telegram, npm/PyPI/Docker tokens, JWTs, PEM/PGP/SSH private key blocks, `Authorization: Bearer` headers, CLI secret flags (`--password`), URL query parameters, and DB connection URIs (`postgres://user:pass@host`).
* **Layer 2 — Universal Key-Value Parser:** Detects sensitive key assignments across `.env`, JSON, YAML, TOML, and source code while preserving structure.
* **Layer 3 — Context-Free Shannon Entropy Scanner:** Catches high-entropy random tokens (`20+` chars) even under innocent variable names (e.g., `FOOBAR="..."`), while filtering out UUIDs, file paths, plain URLs, numbers, and template references (`${VAR}`).
* **Consistent Per-Session Placeholders:** Replaces secrets deterministically per session (e.g., `[REDACTED_STRIPE_KEY_1]`) so the model can reason about code references without ever seeing raw secret values.

---

## Key Modified & Added Files

* `packages/core/src/win32-sandbox.ts` — Native Win32 restricted token, NTFS DACL, and Job Object runner (`opencode-win32-sandbox-v2.exe`).
* `packages/core/src/shell.ts` — Wraps shell execution via `Win32Sandbox.wrapShellSpawn` and redirects temp/cache env vars.
* `packages/core/src/file-access.ts` — Enforces strict `location.directory` realpath confinement.
* `packages/core/src/file-write.ts` — Routes out-of-directory `write`/`edit` attempts through the OS-restricted runner.
* `packages/core/src/dlp/secret-redactor.ts` — Multi-layer regex, KV, and entropy secret redactor.
* `packages/core/src/tool/runtime.ts` — Redacts all tool outputs before returning to the session.
* `packages/core/src/session/model-request.ts` — Redacts `system` and `messages` before dispatching to the LLM.

---

## Quick Start (Development / Standalone)

```powershell
git clone [https://github.com/AmitAzoulay/SecureCode.git](https://github.com/AmitAzoulay/SecureCode.git)
cd SecureCode
bun install

# Typecheck core
bun run --cwd packages/core typecheck

# Launch a confined standalone session on a target directory
bun run --cwd packages/cli src/index.ts --standalone C:\path\to\your\project