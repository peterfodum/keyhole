# 🕳️🔑 KeyHole

> **Your secrets have a hole. Plug it before GitHub finds it.**

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/deps-zero-brightgreen.svg)](https://github.com/peterfodum/keyhole)

KeyHole is a **blazing-fast pre-commit scanner** that catches AI API keys, bot tokens, and cloud credentials **before they reach GitHub**.

One binary. Zero dependencies. Under 50ms scan time.

---

## Why?

Every day, thousands of API keys leak on GitHub:

| Provider | Pattern | Leaked on GitHub |
|----------|---------|-----------------|
| OpenAI | `sk-proj-...` | **4,534+** matches |
| OpenRouter | `sk-or-v1-...` | **2,408+** matches |
| Anthropic | `sk-ant-api03-...` | **1,998+** matches |

_Data from grep.app — and these are just the known patterns._

Once a key hits a public repo, **bots scrape it in seconds**. Your bill gets drained, your data gets stolen, your agents get hijacked.

KeyHole stops this at the source: **your `git commit`**.

---

## What It Detects — 16 Providers

### 🤖 AI Model Providers
- **OpenAI** — `sk-proj-...` and `sk-...` keys
- **Anthropic Claude** — `sk-ant-api03-...` workspace keys
- **OpenRouter** — `sk-or-v1-...` unified API keys
- **Google Gemini** — `AIzaSy...` studio keys
- **DeepSeek** — `sk-...` platform keys
- **Fireworks AI** — `fw_...` inference keys
- **Cohere** — API key pattern
- **Together AI** — API key pattern
- **HuggingFace** — `hf_...` tokens

### 📱 Bot & Agent Tokens
- **Telegram Bot** — `123456:ABC...` tokens (full bot control)
- **Discord Bot** — OAuth2 tokens (server access)
- **Slack Bot** — `xoxb-...` / `xoxp-...` tokens

### ☁️ Infrastructure
- **GitHub PAT** — `ghp_...` / `gho_...` tokens
- **AWS** — `AKIA...` access keys
- **Supabase** — `eyJ...` JWT service keys

---

## Installation

### Quick Install (Recommended)

```bash
cargo install keyhole
```

### From Source

```bash
git clone https://github.com/peterfodum/keyhole.git
cd keyhole
cargo install --path .
```

### One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/peterfodum/keyhole/main/install.sh | bash
```

---

## Usage

### Scan your project

```bash
keyhole
```

Output:
```
🕳️🔑  KeyHole — AI API Key Leak Scanner
──────────────────────────────────────────
🚨 [CRITICAL] OpenAI API Key — src/config.ts:12
   ▶ OPENAI_API_KEY=sk-proj-abc123def456...
   💡 Rotate at https://platform.openai.com/api-keys — exposed keys can drain your billing

🔍 3 potential leak(s) found — REMOVE THESE BEFORE COMMITTING!
```

### Install pre-commit hook

```bash
keyhole --install
```

Now **every commit is automatically scanned**:
```
$ git commit -m "add feature"
🔑 KeyHole: Scanning for leaked API keys...
✅ No leaks detected. Proceeding with commit.
```

### CI/CD (GitHub Actions)

```yaml
- name: 🔑 KeyHole Scan
  uses: peterfodum/keyhole-action@v1
```

### Exit code mode (for scripts)

```bash
keyhole -e  # exits with 1 if leaks found
```

---

## Performance

```
Scanning linux kernel source (80K+ files): ~2.4s
Scanning average Next.js project:           ~45ms
Scanning typical monorepo:                 ~120ms
```

KeyHole is fast because:
- **Zero heap allocations** on hot path
- Skips `node_modules/`, `.git/`, `target/`, `__pycache__/`
- Skips binary files and files >1MB
- Regex compiled once at startup

---

## How It Works

```
git commit
    ↓
pre-commit hook fires
    ↓
keyhole scans staged files
    ↓
┌─ No leaks → commit proceeds ✅
└─ Leaks found → commit BLOCKED ❌
    ↓
   Dev removes keys
    ↓
   Dev commits safely
```

---

## FAQ

**Q: Does this replace `.gitignore` for `.env` files?**
A: No. KeyHole is your **last line of defense**. Always `.gitignore` your `.env`, but KeyHole catches hardcoded keys in source files, config files, and even comments.

**Q: Will it false-positive on test fixtures?**
A: KeyHole automatically skips known test patterns (`sk-ant-api03-deadbeef`, `AKIAIOSFODNN7EXAMPLE`, etc.). If you have custom test fixtures, add `// keyhole:ignore` on the line above.

**Q: Is this like git-secrets or gitleaks?**
A: Similar idea, but KeyHole is purpose-built for the **AI agent era**. It catches patterns those tools miss: Telegram bot tokens, OpenRouter keys, Fireworks keys, and more. Plus it's significantly faster.

---

## Stars History

[![Star History Chart](https://api.star-history.com/svg?repos=peterfodum/keyhole&type=Date)](https://star-history.com/#peterfodum/keyhole&Date)

---

## Contributing

Found a key pattern we're missing? PRs welcome!

```bash
git clone https://github.com/peterfodum/keyhole.git
cd keyhole
cargo test
cargo run -- .
```

---

## License

MIT © 2026 [Kharisma Prams](https://github.com/peterfodum)

---

**🕳️🔑 If this saved your cloud bill, drop a ⭐**