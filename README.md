# ShipSafe

> Scan your AI-built app for security and production-readiness issues — before you ship.

Built a project with Cursor, Claude Code, Lovable, Bolt, or v0? Run ShipSafe before you deploy. It catches the things your AI forgot.

## What it scans

```text
✓ Hardcoded secrets         API keys, tokens, passwords in source code
✓ .env exposure             Missing .gitignore rules, no .env.example
✓ Dangerous NEXT_PUBLIC_    Server secrets leaked to the browser
✓ Wildcard CORS             Access-Control-Allow-Origin: * on APIs
✓ Production console.log    Debug logging left in shipping code
✓ select('*')               Overfetching data from Supabase/Postgres
✓ Missing security headers  No CSP, X-Frame-Options, etc.
✓ Basic config checks       Missing .gitignore, exposed source maps
```

## Quick start

**Claude Code:**
```bash
git clone https://github.com/Marinou92/shipsafe.git ~/.claude/skills/shipsafe
```
Then say: *"Scan this repo with ShipSafe"*

**Codex CLI:**
```bash
git clone https://github.com/Marinou92/shipsafe.git ~/.codex/skills/shipsafe
```

**Standalone (no AI editor):**
```bash
git clone https://github.com/Marinou92/shipsafe.git
cd your-project
python3 path/to/shipsafe/scripts/scan_repo.py --root . --format json
```

## Example output

```text
ShipSafe Report — Score: 47/100

CRITICAL
  [secrets] Hardcoded Stripe key found
    -> src/lib/payments.ts:12
    -> stripe_live_key_redacted

  [secrets] Supabase service role key in client code
    -> src/lib/supabase.ts:3
    -> NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY

WARNING
  [config] .env not in .gitignore
  [config] No .env.example found
  [security] CORS allows all origins
    -> src/app/api/webhook/route.ts:4
  [readiness] 23 console.log statements in production code

SUGGESTION
  [readiness] 4 queries use select('*')
    -> src/app/(dashboard)/posts/page.tsx:18
    -> src/actions/billing.ts:7
  [security] No security headers configured
```

## What's NOT in this free version

This repo covers **secrets and config scanning**. The full version adds:

| | Free (this repo) | Full ShipSafe |
|---|---|---|
| Hardcoded secret detection | ✓ | ✓ |
| .env and .gitignore checks | ✓ | ✓ |
| NEXT_PUBLIC_ audit | ✓ | ✓ |
| CORS and headers check | ✓ | ✓ |
| console.log and select('*') | ✓ | ✓ |
| **Auth logic review** | — | ✓ |
| **getSession() vs getUser() detection** | — | ✓ |
| **Supabase RLS policy analysis** | — | ✓ |
| **SQL migration scanning** | — | ✓ |
| **API handler authorization audit** | — | ✓ |
| **Broken access control detection** | — | ✓ |
| **Ownership check verification** | — | ✓ |
| **npm audit integration** | — | ✓ |
| **Auto-fix mode** | — | ✓ |
| **Baseline suppression** | — | ✓ |
| **Score with category breakdown** | basic | full 3-layer |
| **Reference guides** | — | auth-review.md + fix-playbook.md |

The auth and access control layer is where the real vulnerabilities hide — 45% of AI-generated code ships with security flaws, and most of them are auth-related, not secret-related.

**-> [Get the full ShipSafe ($39)](https://app.lemonsqueezy.com/share/919488)**

## Why this exists

In February 2026, Moltbook — a social network built entirely through vibe coding — exposed 1.5 million API tokens and 35,000 email addresses. The root cause wasn't a hack. It was a misconfigured database that nobody reviewed before shipping.

AI coding tools optimize for making code run, not making code safe. ShipSafe is the review step between "it works" and "it's safe to deploy."

## Works with

| Platform | Status |
|---|---|
| Claude Code | ✓ Skill auto-triggers on "scan" or "audit" |
| OpenAI Codex CLI | ✓ Same SKILL.md format |
| Windsurf | ✓ Copy to skills directory |
| Continue.dev | ✓ Copy to skills directory |
| Standalone CLI | ✓ Run scan_repo.py directly |

## Frameworks detected

The scanner adapts checks based on your stack:

- Next.js (App Router + Pages Router)
- React / Vite
- Node.js / Express
- Supabase
- Firebase
- Any project with a package.json

## Contributing

Found a false positive? A pattern the scanner misses? Open an issue with:

1. The finding (or missed finding)
2. The file content that triggered it
3. Why it's wrong (or right)

PRs welcome for the free scanner. The full version (auth review, auto-fix, RLS analysis) is maintained separately.

## License

MIT — use it however you want.

The full version is sold under a commercial license via [LemonSqueezy](https://app.lemonsqueezy.com/share/919488).

---

**Built by [@Marine_Lucid](https://x.com/Marine_Lucid)** — part of [0toprod](https://0toprod.dev), tools for AI builders.

If this saved your app from shipping a vulnerability, star the repo.
