// packages/core/src/dlp/secret-redactor.ts
import crypto from "node:crypto"

interface SecretRule {
  readonly label: string
  readonly regex: RegExp
  readonly group?: number
}

// ---------------------------------------------------------------------------
// Layer 1: Known Provider & Cryptographic Signatures
// ---------------------------------------------------------------------------
const SIGNATURE_RULES: readonly SecretRule[] = [
  // Cryptographic Private Keys (PEM, OpenSSH, PGP, PKCS8)
  {
    label: "PRIVATE_KEY",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    label: "PGP_PRIVATE_KEY",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
  },
  // AWS Access Key ID & Temporary Session Keys
  {
    label: "AWS_ACCESS_KEY",
    regex: /\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b/g,
    group: 1,
  },
  // GitHub (Classic PAT, Fine-grained PAT, OAuth, App tokens)
  {
    label: "GITHUB_TOKEN",
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
    group: 1,
  },
  // GitLab PAT / Pipeline / Runner Tokens
  {
    label: "GITLAB_TOKEN",
    regex: /\b(glpat-[A-Za-z0-9_-]{20,}|glptt-[A-Za-z0-9_-]{20,}|GR1348941[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
  },
  // OpenAI & Anthropic Keys
  {
    label: "AI_API_KEY",
    regex: /\b(sk-(?:ant-|proj-|svcacct-|live-|test-)?[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
  },
  // HuggingFace Tokens
  {
    label: "HF_TOKEN",
    regex: /\b(hf_[A-Za-z0-9]{30,})\b/g,
    group: 1,
  },
  // Google Cloud / Firebase / Gemini API Keys & OAuth
  {
    label: "GOOGLE_API_KEY",
    regex: /\b(AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,})\b/g,
    group: 1,
  },
  // Slack Tokens & Webhooks
  {
    label: "SLACK_TOKEN",
    regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,}|xoxe\.xox[bp]-[0-9A-Za-z-]{10,})\b/g,
    group: 1,
  },
  {
    label: "SLACK_WEBHOOK",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/([A-Za-z0-9]+)/g,
    group: 1,
  },
  // Discord Bot Tokens & Webhooks
  {
    label: "DISCORD_WEBHOOK",
    regex: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/([A-Za-z0-9_-]{20,})/g,
    group: 1,
  },
  {
    label: "DISCORD_TOKEN",
    regex: /\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})\b/g,
    group: 1,
  },
  // Telegram Bot Token
  {
    label: "TELEGRAM_TOKEN",
    regex: /\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b/g,
    group: 1,
  },
  // Stripe Live & Test Secret/Restricted Keys
  {
    label: "STRIPE_KEY",
    regex: /\b([sr]k_(?:live|test)_[0-9A-Za-z]{16,})\b/g,
    group: 1,
  },
  // NPM, PyPI, NuGet, Docker Hub Tokens
  {
    label: "PACKAGE_REGISTRY_TOKEN",
    regex: /\b(npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}|dckr_pat_[A-Za-z0-9_-]{20,})\b/g,
    group: 1,
  },
  // SendGrid, Mailgun, Twilio, Postman, DigitalOcean, Databricks, Supabase
  {
    label: "CLOUD_SERVICE_TOKEN",
    regex:
      /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|key-[0-9a-zA-Z]{32}|SK[0-9a-fA-F]{32}|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64}|dapi[a-f0-9]{32}|sbp_[a-f0-9]{40})\b/g,
    group: 1,
  },
  // JSON Web Tokens (JWT)
  {
    label: "JWT_TOKEN",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    group: 1,
  },
  // Connection URI / Basic Auth Credentials (postgres://, mongodb://, redis://, https://user:pass@host)
  {
    label: "URI_PASSWORD",
    regex: /\b[a-z][a-z0-9+.-]*:\/\/[^:\s/"'`]+:([^\s@"'`/]{3,})@/gi,
    group: 1,
  },
  // HTTP Authorization Headers (Bearer, Basic, Token, ApiKey)
  {
    label: "AUTH_HEADER",
    regex: /\b(?:Authorization|X-Api-Key|X-Auth-Token)\s*:\s*(?:Bearer\s+|Basic\s+|Token\s+|ApiKey\s+)?([A-Za-z0-9._~+/=-]{12,})/gi,
    group: 1,
  },
  // URL Query Parameters (?api_key=..., &token=..., &client_secret=...)
  {
    label: "URL_QUERY_SECRET",
    regex: /[?&](?:[a-z0-9_.-]*(?:api_?key|token|secret|password|passwd|pwd|auth|access_?key|client_?secret|sig|signature)[a-z0-9_.-]*)=([^&#\s"'`]{6,})/gi,
    group: 1,
  },
  // CLI Flags (--password ..., --api-key=..., -p ...)
  {
    label: "CLI_SECRET_FLAG",
    regex: /(?:^|\s)--?(?:[a-z0-9-]*(?:password|passwd|pwd|secret|token|api-key|apikey|access-key|private-key|client-secret|auth)[a-z0-9-]*)(?:\s+|=)["']?([^\s"'`]{6,})["']?/gi,
    group: 1,
  },
]

// ---------------------------------------------------------------------------
// Layer 2: Universal Key-Value Assignment Pattern (.env, JSON, YAML, TOML, JS/TS/Py)
// Matches ANY identifier containing a sensitive root word anywhere in its name
// ---------------------------------------------------------------------------
const SENSITIVE_KEY_NAME =
  /(?:[a-z0-9_.-]*(?:secret|password|passwd|pwd|passphrase|token|api[_.-]?key|access[_.-]?key|private[_.-]?key|signing[_.-]?key|encryption[_.-]?key|master[_.-]?key|client[_.-]?key|auth[_.-]?key|webhook[_.-]?key|service[_.-]?key|credentials?|auth|bearer|cookie|session[_.-]?id|salt|totp|otp|pin|cvv)[a-z0-9_.-]*)/i

const KV_ASSIGNMENT_RE = new RegExp(
  "([\"']?\\b" +
    SENSITIVE_KEY_NAME.source +
    "\\b[\"']?\\s*(?::=|[:=])\\s*)(?:\"([^\"\\r\\n]{4,})\"|'([^'\\r\\n]{4,})'|([^\\s\"'\\x60,;\\r\\n#}{\\]\\[()]{4,}))",
  "gi",
)

// ---------------------------------------------------------------------------
// False-Positive & Entropy Helpers
// ---------------------------------------------------------------------------
const SAFE_WORDS =
  /^(?:true|false|null|undefined|none|nil|nan|yes|no|on|off|local|localhost|development|production|staging|test|testing|default|example.*|your[_-].*|changeme.*|placeholder.*|dummy.*|todo.*|fixme.*|replace[_-]?me.*|secret|password|token|string|number|boolean|object|required|optional|\*+|x+|\.+|-+)$/i

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// Variable reference or template expression (e.g. ${SECRET}, $SECRET, {{secret}}, process.env.X)
const TEMPLATE_OR_CODE_REF =
  /^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|%[A-Za-z0-9_]+%|process\.env\.[A-Za-z0-9_]+|os\.environ.*|env\(.+\)|std::env.*)$/

function shannonEntropy(str: string): number {
  const counts = new Map<string, number>()
  for (const ch of str) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / str.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function charClasses(str: string): { lower: boolean; upper: boolean; digit: boolean; symbol: boolean } {
  return {
    lower: /[a-z]/.test(str),
    upper: /[A-Z]/.test(str),
    digit: /[0-9]/.test(str),
    symbol: /[^A-Za-z0-9]/.test(str),
  }
}

function isFilePathOrUrl(val: string): boolean {
  if (/^(?:https?|wss?|ftp|file|ssh|git):\/\//i.test(val) && !val.includes("@")) return true
  if (/^(?:[A-Za-z]:\\|\\\\|\/[a-z0-9_.-]+\/|~\/|\.\.?\/|\.\.?\\)/i.test(val)) return true
  // Path with 2+ slashes and common file extensions or path segments (not base64)
  if ((val.match(/[/\\]/g)?.length ?? 0) >= 2 && !val.endsWith("=") && !/[+].*[+]/.test(val)) return true
  if (/\.(?:ts|tsx|js|jsx|json|md|txt|py|go|rs|cs|cpp|h|yaml|yml|toml|html|css|exe|dll|sh|ps1)$/i.test(val))
    return true
  return false
}

function isCodeIdentifier(val: string): boolean {
  // Pure camelCase / PascalCase / snake_case / kebab-case words without random digit mixing
  if (!/[0-9]/.test(val)) {
    // Words made only of letters, underscores, dots, or hyphens with normal entropy
    if (/^[A-Za-z_.-]+$/.test(val) && shannonEntropy(val) < 4.35) return true
  }
  return false
}

function isLikelyFalsePositive(value: string): boolean {
  const trimmed = value.trim()
  if (trimmed.length < 4) return true
  if (trimmed.includes("REDACTED_")) return true
  if (SAFE_WORDS.test(trimmed)) return true
  if (UUID_RE.test(trimmed)) return true
  if (TEMPLATE_OR_CODE_REF.test(trimmed)) return true
  if (/^\d+(?:\.\d+)*$/.test(trimmed)) return true // Pure numbers / versions / ports
  if (new Set(trimmed).size <= 3) return true
  if (isFilePathOrUrl(trimmed)) return true
  return false
}

// ---------------------------------------------------------------------------
// Layer 3: Context-Free High-Entropy Secret Detector
// Catches random secrets even when variable name is "FOO" or standalone in logs
// ---------------------------------------------------------------------------
function isStandaloneHighEntropySecret(candidate: string): boolean {
  if (candidate.length < 20 || candidate.length > 512) return false
  if (isLikelyFalsePositive(candidate)) return false
  if (isCodeIdentifier(candidate)) return false

  const entropy = shannonEntropy(candidate)
  const cls = charClasses(candidate)

  // Case A: Long hex token (32 to 128 hex chars, e.g. MD5/SHA256 API secret, webhook secret)
  if (/^[0-9a-fA-F]{32,128}$/.test(candidate)) {
    return entropy >= 3.3
  }

  // Case B: Mixed alphanumeric/base64url token with upper + lower + digits
  if (cls.lower && cls.upper && cls.digit) {
    // Reject obvious CamelCase English identifiers that happen to have a version number (e.g. GetUserProfileV2Service)
    const digitCount = (candidate.match(/[0-9]/g) ?? []).length
    const transitionCount = (candidate.match(/(?:[a-z][A-Z]|[A-Z][a-z]|[A-Za-z][0-9]|[0-9][A-Za-z])/g) ?? []).length
    if (digitCount >= 2 && transitionCount >= 6 && entropy >= 4.0) {
      return true
    }
    if (entropy >= 4.35) {
      return true
    }
  }

  // Case C: Base64 blob with padding '=' and high entropy
  if (/^[A-Za-z0-9+/]{24,}={1,2}$/.test(candidate) && entropy >= 4.1) {
    return true
  }

  return false
}

export namespace SecretRedactor {
  const sessionTokens = new Map<string, Map<string, string>>()
  const sessionCounters = new Map<string, number>()

  function getPlaceholder(sessionKey: string, label: string, secret: string): string {
    let map = sessionTokens.get(sessionKey)
    if (!map) {
      map = new Map()
      sessionTokens.set(sessionKey, map)
    }
    const digest = crypto.createHash("sha256").update(secret).digest("hex")
    const existing = map.get(digest)
    if (existing) return existing

    const nextIdx = (sessionCounters.get(sessionKey) ?? 0) + 1
    sessionCounters.set(sessionKey, nextIdx)
    const token = `[REDACTED_${label}_${nextIdx}]`
    map.set(digest, token)
    return token
  }

  export function redactText(input: string, sessionID = "global"): { text: string; redactedCount: number } {
    if (!input || input.length < 6) return { text: input, redactedCount: 0 }

    let result = input
    let count = 0

    // Pass 1: Known provider & format signatures
    for (const rule of SIGNATURE_RULES) {
      rule.regex.lastIndex = 0
      result = result.replace(rule.regex, (fullMatch, ...args) => {
        const idx = rule.group
        const secret = idx !== undefined ? (args[idx - 1] as string | undefined) : fullMatch
        if (!secret || isLikelyFalsePositive(secret)) return fullMatch
        count++
        const placeholder = getPlaceholder(sessionID, rule.label, secret)
        return idx === undefined ? placeholder : fullMatch.replace(secret, placeholder)
      })
    }

    // Pass 2: Universal Key-Value assignments (.env, JSON, YAML, TOML, JS/TS/Py)
    KV_ASSIGNMENT_RE.lastIndex = 0
    result = result.replace(KV_ASSIGNMENT_RE, (fullMatch, prefix: string, dqVal?: string, sqVal?: string, bareVal?: string) => {
      const secret = dqVal ?? sqVal ?? bareVal
      if (!secret || isLikelyFalsePositive(secret)) return fullMatch
      count++
      const placeholder = getPlaceholder(sessionID, "SECRET_VALUE", secret)
      if (dqVal !== undefined) return `${prefix}"${placeholder}"`
      if (sqVal !== undefined) return `${prefix}'${placeholder}'`
      return `${prefix}${placeholder}`
    })

    // Pass 3: Context-free standalone high-entropy secrets (even with innocent variable names like FOO="...")
    const standaloneTokenRe = /(?<=^|[\s"'`:=,\[\]{}()<>])([A-Za-z0-9+/=_-]{20,256})(?=$|[\s"'`,;\r\n\[\]{}()<>])/g
    result = result.replace(standaloneTokenRe, (fullMatch, candidate: string) => {
      if (!isStandaloneHighEntropySecret(candidate)) return fullMatch
      count++
      return getPlaceholder(sessionID, "HIGH_ENTROPY_SECRET", candidate)
    })

    return { text: result, redactedCount: count }
  }

  export function redactDeep<T>(value: T, sessionID = "global"): { value: T; redactedCount: number } {
    let total = 0

    function walk(node: unknown): unknown {
      if (typeof node === "string") {
        const res = redactText(node, sessionID)
        total += res.redactedCount
        return res.text
      }
      if (Array.isArray(node)) {
        let changed = false
        const out = node.map((item) => {
          const next = walk(item)
          if (next !== item) changed = true
          return next
        })
        return changed ? out : node
      }
      if (node !== null && typeof node === "object") {
        if (ArrayBuffer.isView(node)) return node
        let changed = false
        const copy: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(node)) {
          const next = walk(v)
          if (next !== v) changed = true
          copy[k] = next
        }
        return changed ? copy : node
      }
      return node
    }

    const redacted = walk(value) as T
    return { value: redacted, redactedCount: total }
  }
}